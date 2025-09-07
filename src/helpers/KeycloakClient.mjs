import fetch from 'node-fetch'


class KeycloakClient {
    #routeConfigs
    #jwksCache
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#routeConfigs = new Map()
        this.#jwksCache = new Map()
    }


    static async createForMultiRealm( { realmsByRoute, silent = false } ) {
        const client = new KeycloakClient( { silent } )
        
        // Initialize all route configurations
        Object.entries( realmsByRoute ).forEach( ( [ route, config ] ) => {
            const normalizedConfig = {
                keycloakUrl: config.keycloakUrl,
                realm: config.realm,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                baseUrl: `${config.keycloakUrl}/realms/${config.realm}`,
                authFlow: config.authFlow || 'authorization_code',
                requiredScopes: config.requiredScopes || [],
                resourceUri: config.resourceUri || ''
            }
            
            client.#routeConfigs.set( route, normalizedConfig )
        } )

        // Preload all JWKS in parallel for performance
        await client.#preloadAllJwks()

        return client
    }


    static create( { keycloakUrl, realm, clientId, clientSecret, silent = false } ) {
        const client = new KeycloakClient( { silent } )
        
        const config = {
            keycloakUrl,
            realm,
            clientId,
            clientSecret,
            baseUrl: `${keycloakUrl}/realms/${realm}`
        }
        
        // For backwards compatibility - store as single route
        client.#routeConfigs.set( 'default', config )

        return client
    }


    async getJwksForRoute( { route } ) {
        const config = this.#getConfigForRoute( { route } )
        
        // Check cache first
        const cacheKey = `${route}-jwks`
        if( this.#jwksCache.has( cacheKey ) ) {
            const cached = this.#jwksCache.get( cacheKey )
            
            // Check if cache is still fresh (5 minutes)
            if( Date.now() - cached.timestamp < 300000 ) {
                return { jwksData: cached.data }
            }
        }

        const jwksUrl = `${config.baseUrl}/protocol/openid-connect/certs`
        
        const response = await fetch( jwksUrl )
        const jwksData = await response.json()

        // Update cache
        this.#jwksCache.set( cacheKey, {
            data: jwksData,
            timestamp: Date.now()
        } )

        if( !this.#silent ) {
            console.log( `JWKS retrieved for route ${route}: ${jwksUrl}` )
        }

        return { jwksData }
    }


    async getRealmInfoForRoute( { route } ) {
        const config = this.#getConfigForRoute( { route } )
        const realmUrl = `${config.keycloakUrl}/admin/realms/${config.realm}`
        
        const { accessToken } = await this.#getAdminTokenForRoute( { route } )
        
        const response = await fetch( realmUrl, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        } )

        const realmData = await response.json()

        return { realmData }
    }


    async validateTokenForRoute( { token, route } ) {
        const config = this.#getConfigForRoute( { route } )
        const introspectUrl = `${config.baseUrl}/protocol/openid-connect/token/introspect`
        
        const params = new URLSearchParams()
        params.append( 'token', token )
        params.append( 'client_id', config.clientId )
        params.append( 'client_secret', config.clientSecret )

        const response = await fetch( introspectUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        } )

        const tokenData = await response.json()

        return { 
            isValid: tokenData.active === true,
            tokenData,
            route
        }
    }


    // Backwards compatibility methods
    async getJwks() {
        return this.getJwksForRoute( { route: 'default' } )
    }


    async getRealmInfo() {
        return this.getRealmInfoForRoute( { route: 'default' } )
    }


    async validateToken( { token } ) {
        return this.validateTokenForRoute( { token, route: 'default' } )
    }


    async #preloadAllJwks() {
        const promises = Array.from( this.#routeConfigs.keys() )
            .map( ( route ) => this.getJwksForRoute( { route } ) )

        try {
            await Promise.all( promises )
            
            if( !this.#silent ) {
                console.log( `Pre-loaded JWKS for ${this.#routeConfigs.size} routes` )
            }
        } catch( error ) {
            if( !this.#silent ) {
                console.warn( `Warning: Some JWKS pre-loading failed: ${error.message}` )
            }
        }
    }


    #getConfigForRoute( { route } ) {
        const config = this.#routeConfigs.get( route )
        
        if( !config ) {
            throw new Error( `No configuration found for route: ${route}` )
        }

        return config
    }


    getAllRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    getRouteConfig( { route } ) {
        return this.#getConfigForRoute( { route } )
    }


    clearJwksCache( { route } ) {
        if( route ) {
            const cacheKey = `${route}-jwks`
            this.#jwksCache.delete( cacheKey )
        } else {
            this.#jwksCache.clear()
        }
    }


    async #getAdminTokenForRoute( { route } ) {
        const config = this.#getConfigForRoute( { route } )
        const tokenUrl = `${config.keycloakUrl}/realms/master/protocol/openid-connect/token`
        
        const params = new URLSearchParams()
        params.append( 'grant_type', 'client_credentials' )
        params.append( 'client_id', config.clientId )
        params.append( 'client_secret', config.clientSecret )

        const response = await fetch( tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        } )

        const tokenData = await response.json()

        return { accessToken: tokenData.access_token }
    }


    // Backwards compatibility
    async #getAdminToken() {
        return this.#getAdminTokenForRoute( { route: 'default' } )
    }
}

export { KeycloakClient }