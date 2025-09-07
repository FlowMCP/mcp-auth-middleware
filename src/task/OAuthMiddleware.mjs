import express from 'express'
import jwt from 'jsonwebtoken'
import fetch from 'node-fetch'

import { DynamicClientRegistration } from './helpers/DynamicClientRegistration.mjs'
import { KeycloakClient } from './helpers/KeycloakClient.mjs'
import { OAuthFlowHandler } from './helpers/OAuthFlowHandler.mjs'
import { TokenValidator } from './helpers/TokenValidator.mjs'


class OAuthMiddleware {
    #routeConfigs
    #routeClients
    #router
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#routeConfigs = new Map()
        this.#routeClients = new Map()
        this.#router = express.Router()
    }


    static async create( { realmsByRoute, silent = false } ) {
        const middleware = new OAuthMiddleware( { silent } )
        
        if( !realmsByRoute || typeof realmsByRoute !== 'object' ) {
            throw new Error( 'realmsByRoute configuration is required' )
        }
        
        // Initialize all routes concurrently
        await middleware.#initializeRoutes( { realmsByRoute } )
        
        // Setup express router with all routes
        middleware.#setupRouter()
        
        return middleware
    }


    async #initializeRoutes( { realmsByRoute } ) {
        // Validate all route configurations first
        const validatedRealmsByRoute = {}
        Object.entries( realmsByRoute ).forEach( ( [ routePath, config ] ) => {
            const validatedConfig = this.#validateRouteConfig( { routePath, config } )
            this.#routeConfigs.set( routePath, validatedConfig )
            validatedRealmsByRoute[routePath] = validatedConfig
        } )

        // Create multi-realm helper instances
        const keycloakClient = await KeycloakClient.createForMultiRealm( { 
            realmsByRoute: validatedRealmsByRoute,
            silent: this.#silent
        } )
        
        const tokenValidator = TokenValidator.createForMultiRealm( { 
            realmsByRoute: validatedRealmsByRoute,
            silent: this.#silent
        } )
        
        // Determine base redirect URI from first route
        const firstRoute = Array.from( this.#routeConfigs.keys() )[0]
        const firstConfig = this.#routeConfigs.get( firstRoute )
        
        // Extract base redirect URI (remove route-specific part)
        let baseRedirectUri = 'http://localhost:3000'
        if( firstConfig.redirectUri ) {
            const url = new URL( firstConfig.redirectUri )
            baseRedirectUri = `${url.protocol}//${url.host}`
        }
        
        const oauthFlowHandler = OAuthFlowHandler.createForMultiRealm( { 
            realmsByRoute: validatedRealmsByRoute,
            baseRedirectUri,
            silent: this.#silent
        } )

        // Store shared helper instances
        this.#routeClients.set( 'shared', {
            keycloakClient,
            tokenValidator,
            oauthFlowHandler
        } )
        
        if( !this.#silent ) {
            console.log( `✅ Initialized ${this.#routeConfigs.size} OAuth routes with shared multi-realm helpers` )
        }
    }


    #validateRouteConfig( { routePath, config } ) {
        if( !routePath || !routePath.startsWith( '/' ) ) {
            throw new Error( `Invalid route path: ${routePath}` )
        }
        
        const required = [ 'keycloakUrl', 'realm', 'clientId', 'clientSecret' ]
        const missing = required.filter( field => !config[field] )
        
        if( missing.length > 0 ) {
            throw new Error( `Missing required fields for route ${routePath}: ${missing.join( ', ' )}` )
        }
        
        // Auto-generate URLs if not provided
        const baseUrl = `${config.keycloakUrl}/realms/${config.realm}`
        
        return {
            ...config,
            routePath,
            
            // OAuth URLs (auto-generated if missing)
            authorizationUrl: config.authorizationUrl || 
                `${baseUrl}/protocol/openid-connect/auth`,
            tokenUrl: config.tokenUrl || 
                `${baseUrl}/protocol/openid-connect/token`,
            jwksUrl: config.jwksUrl || 
                `${baseUrl}/protocol/openid-connect/certs`,
            userInfoUrl: config.userInfoUrl || 
                `${baseUrl}/protocol/openid-connect/userinfo`,
            introspectionUrl: config.introspectionUrl || 
                `${baseUrl}/protocol/openid-connect/token/introspect`,
            
            // Default values
            authFlow: config.authFlow || 'authorization-code',
            requiredScopes: config.requiredScopes || [ 'openid', 'profile' ],
            requiredRoles: config.requiredRoles || [],
            allowAnonymous: config.allowAnonymous || false
        }
    }


    #setupRouter() {
        // OAuth 2.1 Security: HTTPS-only middleware for all OAuth endpoints
        this.#router.use( ( req, res, next ) => {
            if( !this.#isSecureConnection( { req } ) ) {
                return this.#sendHttpsRequiredError( { res } )
            }
            next()
        } )
        
        // Setup routes for each configured realm
        this.#routeConfigs.forEach( ( config, routePath ) => {
            this.#setupRouteEndpoints( { routePath, config } )
        } )
        
        // Setup global well-known endpoints
        this.#setupGlobalWellKnown()
    }


    #setupRouteEndpoints( { routePath, config } ) {
        // OAuth login endpoint per route
        this.#router.get( `${routePath}/auth/login`, ( req, res ) => {
            this.#handleLogin( { req, res, routePath } )
        } )
        
        // OAuth callback endpoint per route  
        this.#router.get( `${routePath}/callback`, async ( req, res ) => {
            await this.#handleCallback( { req, res, routePath } )
        } )
        
        // Route-specific well-known endpoints (RFC 9728)
        this.#router.get( `/.well-known/oauth-protected-resource${routePath}`, ( req, res ) => {
            this.#handleProtectedResourceMetadata( { req, res, routePath } )
        } )
        
        // Route discovery endpoint
        this.#router.get( `${routePath}/discovery`, ( req, res ) => {
            this.#handleRouteDiscovery( { req, res, routePath } )
        } )
        
        // Protected middleware for this route
        this.#router.use( routePath, ( req, res, next ) => {
            this.#handleProtectedRequest( { req, res, next, routePath } )
        } )
    }


    #setupGlobalWellKnown() {
        // Central OAuth Authorization Server metadata (RFC 8414)
        this.#router.get( '/.well-known/oauth-authorization-server', ( req, res ) => {
            this.#handleAuthorizationServerMetadata( { req, res } )
        } )
        
        // Global JWKS endpoint
        this.#router.get( '/.well-known/jwks.json', async ( req, res ) => {
            await this.#handleGlobalJwks( { req, res } )
        } )
    }


    #handleLogin( { req, res, routePath } ) {
        const sharedHelpers = this.#routeClients.get( 'shared' )
        const config = this.#routeConfigs.get( routePath )
        
        // Resource parameter for audience binding (RFC 8707)
        const resourceUri = `${req.protocol}://${req.get( 'host' )}${routePath}`
        
        const { authorizationUrl, state, route } = 
            sharedHelpers.oauthFlowHandler.initiateAuthorizationCodeFlowForRoute( {
                route: routePath,
                scopes: config.requiredScopes,
                resourceIndicators: [ resourceUri ]
            } )
        
        if( !this.#silent ) {
            console.log( `🔐 Login initiated for route ${routePath}, state: ${state}` )
        }
        
        res.redirect( authorizationUrl )
    }


    async #handleCallback( { req, res, routePath } ) {
        const { code, state } = req.query
        const sharedHelpers = this.#routeClients.get( 'shared' )
        
        if( !code || !state ) {
            return res.status( 400 ).json( {
                error: 'invalid_request',
                error_description: 'Missing code or state parameter'
            } )
        }
        
        try {
            const { success, tokens, route, resourceIndicators, error } = await 
                sharedHelpers.oauthFlowHandler.handleAuthorizationCallbackForRoute( {
                    code,
                    state
                } )
            
            if( success ) {
                const config = this.#routeConfigs.get( route )
                
                res.json( {
                    message: 'Authentication successful',
                    route: route,
                    realm: config.realm,
                    access_token: tokens.access_token,
                    token_type: tokens.token_type,
                    expires_in: tokens.expires_in,
                    scope: tokens.scope,
                    resourceIndicators,
                    usage: `Use Bearer token for ${route} endpoints`
                } )
            } else {
                res.status( 400 ).json( {
                    error: 'authentication_failed',
                    error_description: error || 'OAuth callback failed'
                } )
            }
        } catch( callbackError ) {
            if( !this.#silent ) {
                console.error( `❌ Callback error for ${routePath}:`, callbackError )
            }
            
            res.status( 500 ).json( {
                error: 'server_error',
                error_description: 'Internal authentication error'
            } )
        }
    }


    #handleProtectedResourceMetadata( { req, res, routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        const baseUrl = `${req.protocol}://${req.get( 'host' )}`
        const resourceUri = `${baseUrl}${routePath}`
        
        // RFC 9728 Protected Resource Metadata - Complete Implementation
        const metadata = {
            // Required fields per RFC 9728
            resource: resourceUri,
            authorization_servers: [
                `${config.keycloakUrl}/realms/${config.realm}`
            ],
            
            // Optional but recommended fields
            jwks_uri: config.jwksUrl,
            scopes_supported: config.requiredScopes || [],
            resource_documentation: `${baseUrl}${routePath}/discovery`,
            
            // Additional OAuth 2.1 and security information
            bearer_methods_supported: [ 'header' ], // RFC 6750 - Bearer token in Authorization header only
            resource_signing_alg_values_supported: [ 'RS256', 'RS384', 'RS512' ],
            
            // Route-specific metadata
            route_info: {
                path: routePath,
                realm: config.realm,
                auth_flows_supported: [ config.authFlow || 'authorization_code' ],
                client_id: config.clientId,
                required_roles: config.requiredRoles || []
            },
            
            // Links per RFC 9728
            links: [
                {
                    rel: 'authorization_server',
                    href: `${config.keycloakUrl}/realms/${config.realm}`
                },
                {
                    rel: 'login',
                    href: `${baseUrl}${routePath}/auth/login`
                },
                {
                    rel: 'discovery',
                    href: `${baseUrl}${routePath}/discovery`
                }
            ]
        }
        
        // Set proper content type and caching headers
        res.set( {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=300', // 5 minutes cache
            'Access-Control-Allow-Origin': '*', // CORS for discovery
            'Access-Control-Allow-Methods': 'GET',
            'Access-Control-Allow-Headers': 'Authorization'
        } )
        
        res.json( metadata )
    }


    #handleRouteDiscovery( { req, res, routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        const baseUrl = `${req.protocol}://${req.get( 'host' )}`
        
        res.json( {
            route: routePath,
            realm: config.realm,
            authFlow: config.authFlow,
            endpoints: {
                login: `${baseUrl}${routePath}/auth/login`,
                callback: `${baseUrl}${routePath}/callback`,
                protected_resource_metadata: `${baseUrl}/.well-known/oauth-protected-resource${routePath}`
            },
            scopes: {
                required: config.requiredScopes,
                supported: config.requiredScopes
            },
            roles: {
                required: config.requiredRoles
            },
            security: {
                allowAnonymous: config.allowAnonymous,
                authFlow: config.authFlow,
                pkceRequired: true
            }
        } )
    }


    #handleAuthorizationServerMetadata( { req, res } ) {
        // Aggregate metadata from all realms (Gateway pattern)
        const baseUrl = `${req.protocol}://${req.get( 'host' )}`
        
        const realms = Array.from( this.#routeConfigs.values() )
            .reduce( ( acc, config ) => {
                const realmKey = `${config.keycloakUrl}/realms/${config.realm}`
                if( !acc[realmKey] ) {
                    // RFC 8414 compliant Authorization Server Metadata
                    acc[realmKey] = {
                        // Required fields per RFC 8414
                        issuer: realmKey,
                        authorization_endpoint: config.authorizationUrl,
                        token_endpoint: config.tokenUrl,
                        jwks_uri: config.jwksUrl,
                        
                        // Recommended fields
                        userinfo_endpoint: config.userInfoUrl,
                        introspection_endpoint: config.introspectionUrl,
                        response_types_supported: [ 'code' ],
                        grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
                        token_endpoint_auth_methods_supported: [ 'client_secret_post', 'client_secret_basic' ],
                        
                        // Security and OAuth 2.1 compliance
                        code_challenge_methods_supported: [ 'S256' ], // PKCE required
                        scopes_supported: [],
                        response_modes_supported: [ 'query', 'form_post' ],
                        subject_types_supported: [ 'public' ],
                        id_token_signing_alg_values_supported: [ 'RS256', 'RS384', 'RS512' ],
                        
                        // Multi-realm specific
                        routes: [],
                        protected_resources: []
                    }
                }
                
                // Aggregate scopes across routes for this realm
                acc[realmKey].scopes_supported.push( ...config.requiredScopes )
                acc[realmKey].scopes_supported = [...new Set( acc[realmKey].scopes_supported )]
                
                // Add route information
                acc[realmKey].routes.push( config.routePath )
                acc[realmKey].protected_resources.push( {
                    resource_uri: `${baseUrl}${config.routePath}`,
                    metadata_uri: `${baseUrl}/.well-known/oauth-protected-resource${config.routePath}`
                } )
                
                return acc
            }, {} )
        
        // RFC 8414 compliant Gateway metadata with multi-realm support
        const metadata = {
            // Gateway acts as metadata aggregator for all realms
            issuer: baseUrl, // Gateway issuer
            
            // Multi-realm authorization servers
            authorization_servers: Object.values( realms ),
            
            // Gateway endpoints (redirect to appropriate realm based on route)
            authorization_endpoint: `${baseUrl}/oauth/authorize`, // Gateway authorization (route-specific)
            token_endpoint: `${baseUrl}/oauth/token`, // Gateway token (route-specific)
            jwks_uri: `${baseUrl}/.well-known/jwks.json`, // Aggregated JWKS
            
            // RFC 8414 required/recommended fields
            response_types_supported: [ 'code' ],
            grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            token_endpoint_auth_methods_supported: [ 'client_secret_post', 'client_secret_basic' ],
            
            // RFC 8707 Resource Indicators support
            resource_indicators_supported: true,
            
            // OAuth 2.1 Security
            code_challenge_methods_supported: [ 'S256' ], // PKCE required
            response_modes_supported: [ 'query', 'form_post' ],
            scopes_supported: [ 'openid', 'profile', 'email' ],
            
            // Multi-realm specific metadata
            realms_supported: Object.keys( realms ),
            routes_supported: Array.from( this.#routeConfigs.keys() ),
            
            // Route → Realm mapping for client discovery
            route_realm_mapping: Array.from( this.#routeConfigs.entries() )
                .reduce( ( acc, [ route, config ] ) => {
                    acc[route] = {
                        realm: config.realm,
                        issuer: `${config.keycloakUrl}/realms/${config.realm}`,
                        login_endpoint: `${baseUrl}${route}/auth/login`,
                        protected_resource_metadata: `${baseUrl}/.well-known/oauth-protected-resource${route}`
                    }
                    return acc
                }, {} ),
            
            // RFC compliance information
            rfc_compliance: {
                'rfc8414': 'OAuth 2.0 Authorization Server Metadata',
                'rfc9728': 'OAuth 2.0 Protected Resource Metadata',
                'rfc8707': 'OAuth 2.0 Resource Indicators'
            }
        }
        
        // Set proper headers for metadata discovery
        res.set( {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=300', // 5 minutes cache
            'Access-Control-Allow-Origin': '*', // CORS for discovery
            'Access-Control-Allow-Methods': 'GET',
            'Access-Control-Allow-Headers': 'Authorization'
        } )
        
        res.json( metadata )
    }


    async #handleGlobalJwks( { req, res } ) {
        try {
            const sharedHelpers = this.#routeClients.get( 'shared' )
            
            // Aggregate JWKS from all routes/realms
            const jwkPromises = Array.from( this.#routeConfigs.keys() )
                .map( async ( route ) => {
                    try {
                        const { jwksData } = await sharedHelpers.keycloakClient.getJwksForRoute( { route } )
                        return jwksData.keys || []
                    } catch( error ) {
                        if( !this.#silent ) {
                            console.warn( `Failed to load JWKS for route ${route}: ${error.message}` )
                        }
                        return []
                    }
                } )
            
            const jwkArrays = await Promise.all( jwkPromises )
            const allKeys = jwkArrays.flat()
            
            // Remove duplicates based on kid (key ID)
            const uniqueKeys = allKeys.reduce( ( acc, key ) => {
                if( key.kid && !acc.find( k => k.kid === key.kid ) ) {
                    acc.push( key )
                }
                return acc
            }, [] )
            
            // Set proper JWKS headers
            res.set( {
                'Content-Type': 'application/jwk-set+json',
                'Cache-Control': 'public, max-age=300', // 5 minutes cache
                'Access-Control-Allow-Origin': '*', // CORS for JWKS
                'Access-Control-Allow-Methods': 'GET'
            } )
            
            res.json( { keys: uniqueKeys } )
        } catch( error ) {
            if( !this.#silent ) {
                console.error( '❌ Global JWKS error:', error )
            }
            
            res.status( 500 ).json( {
                error: 'server_error',
                error_description: 'Failed to load JWKS'
            } )
        }
    }


    async #handleProtectedRequest( { req, res, next, routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        const sharedHelpers = this.#routeClients.get( 'shared' )
        
        // Check if route allows anonymous access
        if( config.allowAnonymous && !req.headers.authorization ) {
            req.user = { anonymous: true }
            req.authRealm = config.realm
            req.authRoute = routePath
            return next()
        }
        
        // OAuth 2.1 Security: Validate Bearer token format and security requirements
        const bearerValidation = this.#validateBearerTokenSecurity( { req } )
        if( !bearerValidation.isValid ) {
            return this.#sendUnauthorized( { 
                res, 
                routePath, 
                reason: bearerValidation.description || bearerValidation.error 
            } )
        }
        
        const token = bearerValidation.token
        
        // Validate token against route's realm with audience binding (RFC 8707)
        const resourceUri = `${req.protocol}://${req.get( 'host' )}${routePath}`
        const validationResult = await sharedHelpers.tokenValidator.validateWithAudienceBinding( { 
            token, 
            route: routePath, 
            resourceUri 
        } )
        
        if( !validationResult.isValid ) {
            return this.#sendUnauthorized( { res, routePath, reason: validationResult.error || 'invalid_token' } )
        }
        
        // Check audience binding result
        if( validationResult.audienceBinding && !validationResult.audienceBinding.isValidAudience ) {
            return this.#sendForbidden( { res, routePath, reason: 'invalid_audience' } )
        }
        
        // Check route-specific roles and scopes
        const authzCheck = this.#checkAuthorization( { decoded: validationResult.decoded, config } )
        if( !authzCheck.allowed ) {
            return this.#sendForbidden( { res, routePath, reason: authzCheck.reason } )
        }
        
        // Set request context
        req.user = validationResult.decoded
        req.authRealm = config.realm
        req.authRoute = routePath
        req.scopes = validationResult.decoded.scope ? validationResult.decoded.scope.split( ' ' ) : []
        req.roles = validationResult.decoded.realm_access?.roles || []
        
        next()
    }


    #extractBearerToken( { authHeader } ) {
        if( !authHeader.startsWith( 'Bearer ' ) ) {
            return null
        }
        
        return authHeader.slice( 7 ).trim()
    }


    // Note: #validateAudienceBinding logic moved to TokenValidator.validateWithAudienceBinding


    #checkAuthorization( { decoded, config } ) {
        // Check required roles
        if( config.requiredRoles.length > 0 ) {
            const userRoles = decoded.realm_access?.roles || []
            const hasRequiredRole = config.requiredRoles.some( 
                role => userRoles.includes( role ) 
            )
            
            if( !hasRequiredRole ) {
                return { 
                    allowed: false, 
                    reason: `Missing required role: ${config.requiredRoles.join( ' or ' )}` 
                }
            }
        }
        
        // Check required scopes
        if( config.requiredScopes.length > 0 ) {
            const userScopes = decoded.scope ? decoded.scope.split( ' ' ) : []
            const hasRequiredScope = config.requiredScopes.some( 
                scope => userScopes.includes( scope ) 
            )
            
            if( !hasRequiredScope ) {
                return { 
                    allowed: false, 
                    reason: `Missing required scope: ${config.requiredScopes.join( ' or ' )}` 
                }
            }
        }
        
        return { allowed: true }
    }


    #sendUnauthorized( { res, routePath, reason } ) {
        const baseUrl = `${res.req.protocol}://${res.req.get( 'host' )}`
        const prmUrl = `${baseUrl}/.well-known/oauth-protected-resource${routePath}`
        
        // RFC 9728 compliant 401 response
        res.set( 'WWW-Authenticate', `Bearer realm="${routePath}", error="invalid_token", error_description="${reason}", resource_metadata="${prmUrl}"` )
        
        res.status( 401 ).json( {
            error: 'unauthorized',
            error_description: reason,
            route: routePath,
            protected_resource_metadata: prmUrl,
            login_url: `${baseUrl}${routePath}/auth/login`
        } )
    }


    #sendForbidden( { res, routePath, reason } ) {
        const config = this.#routeConfigs.get( routePath )
        const baseUrl = `${res.req.protocol}://${res.req.get( 'host' )}`
        const prmUrl = `${baseUrl}/.well-known/oauth-protected-resource${routePath}`
        
        // RFC 9728 compliant 403 response with WWW-Authenticate header
        const authHeaderParts = [
            `Bearer realm="${routePath}"`,
            `error="insufficient_scope"`,
            `error_description="${reason}"`,
            `resource_metadata="${prmUrl}"`
        ]
        
        // Add scope information if it's a scope-related error
        if( reason.includes( 'scope' ) && config.requiredScopes.length > 0 ) {
            authHeaderParts.push( `scope="${config.requiredScopes.join( ' ' )}"` )
        }
        
        res.set( 'WWW-Authenticate', authHeaderParts.join( ', ' ) )
        
        res.status( 403 ).json( {
            error: 'forbidden',
            error_description: reason,
            route: routePath,
            required_scopes: config.requiredScopes,
            required_roles: config.requiredRoles,
            protected_resource_metadata: prmUrl
        } )
    }


    // OAuth 2.1 Security Methods


    #isSecureConnection( { req } ) {
        // Check if connection is secure
        if( req.secure ) {
            return true
        }
        
        // Check X-Forwarded-Proto header for proxy/load balancer scenarios
        const forwardedProto = req.get( 'X-Forwarded-Proto' )
        if( forwardedProto === 'https' ) {
            return true
        }
        
        // For local development, allow localhost
        if( process.env.NODE_ENV === 'development' ) {
            const host = req.get( 'host' ) || ''
            if( host.includes( 'localhost' ) || host.includes( '127.0.0.1' ) ) {
                if( !this.#silent ) {
                    console.warn( '⚠️  HTTPS requirement bypassed for local development' )
                }
                return true
            }
        }
        
        return false
    }


    #sendHttpsRequiredError( { res } ) {
        res.set( {
            'Content-Type': 'application/json',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        } )
        
        res.status( 400 ).json( {
            error: 'invalid_request',
            error_description: 'OAuth 2.1 requires HTTPS for all endpoints. Please use https:// instead of http://',
            oauth_compliance: 'OAuth 2.1 Section 3.1',
            documentation: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics'
        } )
    }


    #validateBearerTokenSecurity( { req } ) {
        const authHeader = req.get( 'authorization' )
        
        if( !authHeader ) {
            return {
                isValid: false,
                error: 'missing_authorization_header'
            }
        }
        
        // OAuth 2.1: Bearer tokens only, no URL parameters
        if( !authHeader.startsWith( 'Bearer ' ) ) {
            return {
                isValid: false,
                error: 'invalid_token_format',
                description: 'OAuth 2.1 requires Bearer token format in Authorization header'
            }
        }
        
        // Check for token in URL parameters (forbidden by OAuth 2.1)
        if( req.query.access_token || req.body?.access_token ) {
            return {
                isValid: false,
                error: 'token_in_url_forbidden',
                description: 'OAuth 2.1 prohibits access tokens in URL parameters or form body'
            }
        }
        
        const token = authHeader.substring( 7 ) // Remove 'Bearer '
        
        if( !token ) {
            return {
                isValid: false,
                error: 'empty_bearer_token'
            }
        }
        
        return {
            isValid: true,
            token
        }
    }


    #validatePKCERequirements( { codeChallenge, codeChallengeMethod } ) {
        // OAuth 2.1: PKCE is mandatory for authorization code flow
        if( !codeChallenge ) {
            return {
                isValid: false,
                error: 'missing_code_challenge',
                description: 'OAuth 2.1 requires PKCE for authorization code flow'
            }
        }
        
        if( !codeChallengeMethod ) {
            return {
                isValid: false,
                error: 'missing_code_challenge_method',
                description: 'OAuth 2.1 requires code_challenge_method parameter'
            }
        }
        
        // OAuth 2.1: Only S256 method is allowed
        if( codeChallengeMethod !== 'S256' ) {
            return {
                isValid: false,
                error: 'invalid_code_challenge_method',
                description: 'OAuth 2.1 only supports S256 for code_challenge_method'
            }
        }
        
        return {
            isValid: true
        }
    }


    // Public API


    router() {
        return this.#router
    }


    getRouteConfig( routePath ) {
        return this.#routeConfigs.get( routePath )
    }


    getRouteClient( routePath ) {
        return this.#routeClients.get( routePath )
    }


    getRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    getRealms() {
        return Array.from( this.#routeConfigs.values() ).map( config => ({
            route: config.routePath,
            realm: config.realm,
            keycloakUrl: config.keycloakUrl,
            resourceUri: config.resourceUri,
            requiredScopes: config.requiredScopes
        }) )
    }
}

export { OAuthMiddleware }