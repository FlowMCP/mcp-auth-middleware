import fetch from 'node-fetch'

import { Logger } from './Logger.mjs'


class DynamicClientRegistration {
    #config
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
    }


    static create( { keycloakUrl, realm, silent = false } ) {
        const registration = new DynamicClientRegistration( { silent } )
        
        const config = {
            keycloakUrl,
            realm,
            registrationEndpoint: `${keycloakUrl}/realms/${realm}/clients-registrations/openid-connect`
        }
        
        registration.#config = config

        return registration
    }


    async registerClient( { 
        clientName, 
        redirectUris = [], 
        grantTypes = [ 'authorization_code', 'refresh_token' ],
        responseTypes = [ 'code' ],
        tokenEndpointAuthMethod = 'none',
        applicationName = 'MCP Client',
        contacts = [],
        logoUri = null,
        policyUri = null,
        tosUri = null
    } ) {
        const clientMetadata = {
            client_name: clientName,
            redirect_uris: redirectUris,
            grant_types: grantTypes,
            response_types: responseTypes,
            token_endpoint_auth_method: tokenEndpointAuthMethod,
            application_type: 'native',
            require_auth_time: false,
            default_max_age: 3600
        }
        
        if( applicationName ) {
            clientMetadata.application_name = applicationName
        }
        
        if( contacts.length > 0 ) {
            clientMetadata.contacts = contacts
        }
        
        if( logoUri ) {
            clientMetadata.logo_uri = logoUri
        }
        
        if( policyUri ) {
            clientMetadata.policy_uri = policyUri
        }
        
        if( tosUri ) {
            clientMetadata.tos_uri = tosUri
        }
        
        const response = await fetch( this.#config.registrationEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify( clientMetadata )
        } )
        
        const registrationResponse = await response.json()
        
        if( registrationResponse.error ) {
            return {
                success: false,
                error: registrationResponse.error_description || 'Registration failed'
            }
        }
        
        Logger.success( { 
            silent: this.#silent, 
            message: `Client registered successfully: ${registrationResponse.client_id}` 
        } )

        return {
            success: true,
            clientId: registrationResponse.client_id,
            clientSecret: registrationResponse.client_secret,
            registrationAccessToken: registrationResponse.registration_access_token,
            registrationClientUri: registrationResponse.registration_client_uri,
            metadata: registrationResponse
        }
    }


    async updateClient( { clientId, registrationAccessToken, updates } ) {
        const response = await fetch( `${this.#config.registrationEndpoint}/${clientId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${registrationAccessToken}`
            },
            body: JSON.stringify( updates )
        } )
        
        const updateResponse = await response.json()
        
        if( updateResponse.error ) {
            return {
                success: false,
                error: updateResponse.error_description || 'Update failed'
            }
        }

        return {
            success: true,
            metadata: updateResponse
        }
    }


    async deleteClient( { clientId, registrationAccessToken } ) {
        const response = await fetch( `${this.#config.registrationEndpoint}/${clientId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${registrationAccessToken}`
            }
        } )
        
        if( response.status === 204 ) {
            Logger.success( { 
                silent: this.#silent, 
                message: `Client ${clientId} deleted successfully` 
            } )
            
            return { success: true }
        }

        return {
            success: false,
            error: 'Deletion failed'
        }
    }
}

export { DynamicClientRegistration }