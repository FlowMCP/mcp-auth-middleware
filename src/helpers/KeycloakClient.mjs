import fetch from 'node-fetch'


class KeycloakClient {
    #config
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
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
        
        client.#config = config

        return client
    }


    async getJwks() {
        const jwksUrl = `${this.#config.baseUrl}/protocol/openid-connect/certs`
        
        const response = await fetch( jwksUrl )
        const jwksData = await response.json()

        if( !this.#silent ) {
            console.log( `JWKS retrieved from: ${jwksUrl}` )
        }

        return { jwksData }
    }


    async getRealmInfo() {
        const realmUrl = `${this.#config.keycloakUrl}/admin/realms/${this.#config.realm}`
        
        const { accessToken } = await this.#getAdminToken()
        
        const response = await fetch( realmUrl, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        } )

        const realmData = await response.json()

        return { realmData }
    }


    async validateToken( { token } ) {
        const introspectUrl = `${this.#config.baseUrl}/protocol/openid-connect/token/introspect`
        
        const params = new URLSearchParams()
        params.append( 'token', token )
        params.append( 'client_id', this.#config.clientId )
        params.append( 'client_secret', this.#config.clientSecret )

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
            tokenData
        }
    }


    async #getAdminToken() {
        const tokenUrl = `${this.#config.keycloakUrl}/realms/master/protocol/openid-connect/token`
        
        const params = new URLSearchParams()
        params.append( 'grant_type', 'client_credentials' )
        params.append( 'client_id', this.#config.clientId )
        params.append( 'client_secret', this.#config.clientSecret )

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
}

export { KeycloakClient }