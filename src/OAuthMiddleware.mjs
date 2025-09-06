import jwt from 'jsonwebtoken'
import fetch from 'node-fetch'

import { DynamicClientRegistration } from './helpers/DynamicClientRegistration.mjs'
import { KeycloakClient } from './helpers/KeycloakClient.mjs'
import { OAuthFlowHandler } from './helpers/OAuthFlowHandler.mjs'
import { TokenValidator } from './helpers/TokenValidator.mjs'


class OAuthMiddleware {
    #keycloakClient
    #tokenValidator
    #oauthFlowHandler
    #dynamicClientRegistration
    #config
    #silent
    #rbacRules


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#rbacRules = new Map()
    }


    static create( { keycloakUrl, realm, clientId, clientSecret, redirectUri, silent = false } ) {
        const middleware = new OAuthMiddleware( { silent } )
        
        const config = {
            keycloakUrl,
            realm,
            clientId,
            clientSecret,
            redirectUri
        }

        const keycloakClient = KeycloakClient.create( { ...config, silent } )
        const tokenValidator = TokenValidator.create( { ...config, silent } )
        const oauthFlowHandler = OAuthFlowHandler.create( { ...config, silent } )
        const dynamicClientRegistration = DynamicClientRegistration.create( { 
            keycloakUrl, 
            realm, 
            silent 
        } )

        middleware.#config = config
        middleware.#keycloakClient = keycloakClient
        middleware.#tokenValidator = tokenValidator
        middleware.#oauthFlowHandler = oauthFlowHandler
        middleware.#dynamicClientRegistration = dynamicClientRegistration

        return { middleware }
    }


    mcp() {
        return ( req, res, next ) => {
            this.#handleRequest( { req, res, next } )
        }
    }


    wellKnownAuthorizationServer() {
        return ( req, res ) => {
            this.#handleWellKnownAuthorizationServer( { req, res } )
        }
    }


    wellKnownProtectedResource() {
        return ( req, res ) => {
            this.#handleWellKnownProtectedResource( { req, res } )
        }
    }


    wellKnownJwks() {
        return ( req, res ) => {
            this.#handleWellKnownJwks( { req, res } )
        }
    }


    #handleRequest( { req, res, next } ) {
        const authHeader = req.headers.authorization

        if( !authHeader ) {
            res.status( 401 ).json( { error: 'Authorization header required' } )
            return
        }

        const token = this.#extractBearerToken( { authHeader } )
        if( !token ) {
            res.status( 401 ).json( { error: 'Invalid authorization header format' } )
            return
        }

        const { isValid, decoded, error } = this.#tokenValidator.validate( { token } )
        
        if( !isValid ) {
            res.status( 401 ).json( { error: error || 'Invalid token' } )
            return
        }

        req.user = decoded
        next()
    }


    #extractBearerToken( { authHeader } ) {
        if( !authHeader.startsWith( 'Bearer ' ) ) {
            return null
        }
        
        const token = authHeader.slice( 7 )
        
        return token
    }


    #handleWellKnownAuthorizationServer( { req, res } ) {
        const metadata = {
            issuer: `${this.#config.keycloakUrl}/realms/${this.#config.realm}`,
            authorization_endpoint: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/auth`,
            token_endpoint: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/token`,
            jwks_uri: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/certs`,
            userinfo_endpoint: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/userinfo`,
            end_session_endpoint: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/logout`,
            registration_endpoint: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/clients-registrations/openid-connect`,
            scopes_supported: [ 'openid', 'profile', 'email', 'mcp:tools', 'mcp:resources' ],
            response_types_supported: [ 'code' ],
            grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            code_challenge_methods_supported: [ 'S256' ],
            token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ]
        }

        res.json( metadata )
    }


    #handleWellKnownProtectedResource( { req, res } ) {
        const metadata = {
            resource: `${this.#config.keycloakUrl}/realms/${this.#config.realm}`,
            authorization_servers: [
                `${this.#config.keycloakUrl}/realms/${this.#config.realm}`
            ],
            jwks_uri: `${this.#config.keycloakUrl}/realms/${this.#config.realm}/protocol/openid-connect/certs`,
            scopes_supported: [ 'mcp:tools', 'mcp:resources', 'mcp:tools:weather', 'mcp:resources:read' ]
        }

        res.json( metadata )
    }


    #handleWellKnownJwks( { req, res } ) {
        const { jwksData } = this.#keycloakClient.getJwks()
        
        res.json( jwksData )
    }


    // OAuth Flows
    initiateAuthorizationCodeFlow( { scopes, resourceIndicators } ) {
        return this.#oauthFlowHandler.initiateAuthorizationCodeFlow( { 
            scopes, 
            resourceIndicators 
        } )
    }


    async handleAuthorizationCallback( { code, state } ) {
        return await this.#oauthFlowHandler.handleAuthorizationCallback( { 
            code, 
            state 
        } )
    }


    async requestClientCredentials( { scopes } ) {
        return await this.#oauthFlowHandler.requestClientCredentials( { scopes } )
    }


    async refreshAccessToken( { refreshToken } ) {
        return await this.#oauthFlowHandler.refreshAccessToken( { refreshToken } )
    }


    // Dynamic Client Registration
    async registerClient( { clientName, redirectUris, grantTypes } ) {
        return await this.#dynamicClientRegistration.registerClient( { 
            clientName, 
            redirectUris, 
            grantTypes 
        } )
    }


    // RBAC Configuration
    setRBACRules( { rules } ) {
        rules.forEach( ( rule ) => {
            this.#rbacRules.set( rule.path, rule )
        } )

        return { success: true }
    }


    checkRBAC( { path, method, roles, scopes } ) {
        const rule = this.#rbacRules.get( path )
        
        if( !rule ) {
            return { allowed: true }
        }
        
        if( rule.methods && !rule.methods.includes( method ) ) {
            return { allowed: false, reason: 'Method not allowed' }
        }
        
        if( rule.requiredRoles ) {
            const hasRole = rule.requiredRoles.some( ( role ) => roles.includes( role ) )
            if( !hasRole ) {
                return { allowed: false, reason: 'Missing required role' }
            }
        }
        
        if( rule.requiredScopes ) {
            const hasScope = rule.requiredScopes.some( ( scope ) => scopes.includes( scope ) )
            if( !hasScope ) {
                return { allowed: false, reason: 'Missing required scope' }
            }
        }

        return { allowed: true }
    }


    // Enhanced middleware with RBAC
    mcpWithRBAC() {
        return ( req, res, next ) => {
            const authHeader = req.headers.authorization

            if( !authHeader ) {
                res.status( 401 ).json( { error: 'Authorization header required' } )
                return
            }

            const token = this.#extractBearerToken( { authHeader } )
            if( !token ) {
                res.status( 401 ).json( { error: 'Invalid authorization header format' } )
                return
            }

            const { isValid, decoded, error } = this.#tokenValidator.validate( { token } )
            
            if( !isValid ) {
                res.status( 401 ).json( { error: error || 'Invalid token' } )
                return
            }

            const roles = decoded.realm_access?.roles || []
            const scopes = decoded.scope ? decoded.scope.split( ' ' ) : []
            
            const { allowed, reason } = this.checkRBAC( {
                path: req.path,
                method: req.method,
                roles,
                scopes
            } )
            
            if( !allowed ) {
                res.status( 403 ).json( { error: reason || 'Access denied' } )
                return
            }

            req.user = decoded
            req.roles = roles
            req.scopes = scopes
            next()
        }
    }
}

export { OAuthMiddleware }