import { Logger } from '../helpers/Logger.mjs'


class McpOAuthDiscoveryHandler {
    #routes
    #silent


    constructor( { routes, silent = false } ) {
        this.#routes = routes
        this.#silent = silent
    }


    static create( { routes, silent = false } ) {
        return new McpOAuthDiscoveryHandler( { routes, silent } )
    }


    generateAuthorizationServerMetadata( { routePath } ) {
        const routeConfig = this.#routes[ routePath ]
        
        if( !routeConfig ) {
            return { 
                success: false, 
                error: `Route ${routePath} not found` 
            }
        }

        const { providerUrl, scope } = routeConfig
        const scopes = scope ? scope.split( ' ' ) : [ 'openid', 'profile', 'email' ]

        const metadata = {
            issuer: providerUrl,
            authorization_endpoint: `${providerUrl}/authorize`,
            token_endpoint: `${providerUrl}/oauth/token`,
            userinfo_endpoint: `${providerUrl}/userinfo`,
            jwks_uri: `${providerUrl}/.well-known/jwks.json`,
            scopes_supported: scopes,
            response_types_supported: [ 'code' ],
            response_modes_supported: [ 'query', 'fragment' ],
            grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            code_challenge_methods_supported: [ 'S256' ],
            token_endpoint_auth_methods_supported: [ 'none', 'client_secret_post' ],
            subject_types_supported: [ 'public' ],
            id_token_signing_alg_values_supported: [ 'RS256' ]
        }

        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `Generated OAuth authorization server metadata for ${routePath}` 
            } )
        }

        return { 
            success: true, 
            metadata 
        }
    }


    generateProtectedResourceMetadata( { routePath } ) {
        const routeConfig = this.#routes[ routePath ]
        
        if( !routeConfig ) {
            return { 
                success: false, 
                error: `Route ${routePath} not found` 
            }
        }

        const { providerUrl, audience, scope } = routeConfig
        const scopes = scope ? scope.split( ' ' ) : [ 'openid', 'profile', 'email' ]

        const metadata = {
            resource: audience || `http://localhost:3000${routePath}`,
            authorization_servers: [ providerUrl ],
            scopes_supported: scopes,
            bearer_methods_supported: [ 'header' ],
            resource_documentation: `MCP OAuth protected resource for ${routePath}`
        }

        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `Generated OAuth protected resource metadata for ${routePath}` 
            } )
        }

        return { 
            success: true, 
            metadata 
        }
    }


    createDiscoveryRoutes( { app } ) {
        const routePaths = Object.keys( this.#routes )

        routePaths
            .forEach( ( routePath ) => {
                const authServerPath = `${routePath}/.well-known/oauth-authorization-server`
                const protectedResourcePath = `${routePath}/.well-known/oauth-protected-resource`

                app.get( authServerPath, ( req, res ) => {
                    const { success, metadata, error } = this.generateAuthorizationServerMetadata( { routePath } )
                    
                    if( !success ) {
                        return res.status( 404 ).json( { error } )
                    }

                    res.set( {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'public, max-age=3600'
                    } )
                    
                    res.json( metadata )
                } )

                app.get( protectedResourcePath, ( req, res ) => {
                    const { success, metadata, error } = this.generateProtectedResourceMetadata( { routePath } )
                    
                    if( !success ) {
                        return res.status( 404 ).json( { error } )
                    }

                    res.set( {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'public, max-age=3600'
                    } )
                    
                    res.json( metadata )
                } )

                if( !this.#silent ) {
                    Logger.info( { 
                        silent: this.#silent, 
                        message: `Registered discovery endpoints for ${routePath}` 
                    } )
                }
            } )

        return { 
            success: true, 
            registeredRoutes: routePaths.length 
        }
    }


    getRoutes() {
        return { ...this.#routes }
    }
}

export { McpOAuthDiscoveryHandler }