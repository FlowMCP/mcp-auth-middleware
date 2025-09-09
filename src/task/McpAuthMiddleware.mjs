import express from 'express'
import jwt from 'jsonwebtoken'
// Using native fetch (Node.js 22+)

import { AuthTypeFactory } from '../core/AuthTypeFactory.mjs'
import { DynamicClientRegistration } from '../helpers/DynamicClientRegistration.mjs'
import { Logger } from '../helpers/Logger.mjs'
import { OAuthFlowHandler } from '../helpers/OAuthFlowHandler.mjs'
import { TokenValidator } from '../helpers/TokenValidator.mjs'
import { Validation } from './Validation.mjs'


class McpAuthMiddleware {
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


    static async create( { routes, silent = false } ) {
        const middleware = new McpAuthMiddleware( { silent } )
        
        if( !routes || typeof routes !== 'object' ) {
            throw new Error( 'routes configuration is required' )
        }
        
        // Initialize all routes concurrently
        await middleware.#initializeRoutes( { routes } )
        
        // Setup express router with all routes
        middleware.#setupRouter()
        
        return middleware
    }


    async #initializeRoutes( { routes } ) {
        // Validate that routes is not empty
        if( Object.keys( routes ).length === 0 ) {
            throw new Error( 'No routes configured - at least one route is required' )
        }
        
        // Validate all route configurations first
        const validatedRoutes = {}
        Object.entries( routes ).forEach( ( [ routePath, config ] ) => {
            const validatedConfig = this.#validateRouteConfig( { routePath, config } )
            this.#routeConfigs.set( routePath, validatedConfig )
            validatedRoutes[routePath] = validatedConfig
        } )

        // Create AuthType-based handlers for all routes
        const authHandlers = {}
        
        for( const [ routePath, config ] of this.#routeConfigs.entries() ) {
            try {
                const authHandler = await AuthTypeFactory.createAuthHandler( { 
                    authType: config.authType, 
                    config,
                    silent: this.#silent 
                } )
                authHandlers[routePath] = authHandler
            } catch( error ) {
                throw new Error( `Failed to create AuthType handler for route ${routePath}: ${error.message}` )
            }
        }
        
        const tokenValidator = TokenValidator.createForMultiRealm( { 
            routes: validatedRoutes,
            silent: this.#silent
        } )
        
        // Determine base redirect URI from first route
        const firstRoute = Array.from( this.#routeConfigs.keys() )[0]
        const firstConfig = this.#routeConfigs.get( firstRoute )
        
        // Extract base redirect URI from resourceUri or use default
        let baseRedirectUri = 'http://localhost:3000'
        if( firstConfig.resourceUri ) {
            const url = new URL( firstConfig.resourceUri )
            baseRedirectUri = `${url.protocol}//${url.host}`
        }
        
        // Filter routes to only include OAuth-based AuthTypes for FlowHandler
        const oauthRoutes = Object.fromEntries(
            Object.entries( validatedRoutes )
                .filter( ( [ route, config ] ) => config.authType && config.authType.includes( 'oauth' ) )
        )

        let oauthFlowHandler = null
        if( Object.keys( oauthRoutes ).length > 0 ) {
            oauthFlowHandler = OAuthFlowHandler.createForMultiRealm( { 
                routes: oauthRoutes,
                baseRedirectUri,
                silent: this.#silent
            } )
        }

        // Store shared helper instances (AuthType-based system)
        this.#routeClients.set( 'shared', {
            authHandlers,
            tokenValidator,
            oauthFlowHandler
        } )
        
        if( !this.#silent ) {
            this.#displayRoutesSummary()
        }
    }


    #validateRouteConfig( { routePath, config } ) {
        if( !routePath || !routePath.startsWith( '/' ) ) {
            throw new Error( `Must start with "/" - Invalid route path: ${routePath}` )
        }
        
        // Use new Validation system for authType-based or legacy validation
        const validationResult = Validation.validationCreate( { 
            routes: { [routePath]: config },
            silent: this.#silent 
        } )
        
        if( !validationResult.status ) {
            throw new Error( `Route validation failed: ${validationResult.messages.join( ', ' )}` )
        }
        
        // Use AuthType-based configuration or legacy provider detection
        let finalConfig
        
        if( config.authType ) {
            // New AuthType-based approach
            finalConfig = {
                ...config,
                routePath,
                realm: this.#deriveRealmName( { routePath } ),
                authFlow: config.authFlow || 'authorization-code',
                requiredRoles: config.requiredRoles || [],
                allowAnonymous: config.allowAnonymous || false
            }
        } else {
            // Legacy provider-based approach (backwards compatibility)
            let baseUrl, authorizationUrl, tokenUrl, jwksUrl, userInfoUrl, introspectionUrl
            
            // Detect Auth0
            if( config.providerUrl.includes( 'auth0.com' ) ) {
                baseUrl = config.providerUrl
                authorizationUrl = `${baseUrl}/authorize`
                tokenUrl = `${baseUrl}/oauth/token`
                jwksUrl = `${baseUrl}/.well-known/jwks.json`
                userInfoUrl = `${baseUrl}/userinfo`
                introspectionUrl = `${baseUrl}/oauth/token/introspection`
            } else {
                // Keycloak/standard OIDC
                baseUrl = `${config.providerUrl}/realms/${config.realm}`
                authorizationUrl = `${baseUrl}/protocol/openid-connect/auth`
                tokenUrl = `${baseUrl}/protocol/openid-connect/token`
                jwksUrl = `${baseUrl}/protocol/openid-connect/certs`
                userInfoUrl = `${baseUrl}/protocol/openid-connect/userinfo`
                introspectionUrl = `${baseUrl}/protocol/openid-connect/token/introspect`
            }
            
            finalConfig = {
                ...config,
                routePath,
                
                // OAuth URLs (auto-generated if missing)
                authorizationUrl: config.authorizationUrl || authorizationUrl,
                tokenUrl: config.tokenUrl || tokenUrl,
                jwksUrl: config.jwksUrl || jwksUrl,
                userInfoUrl: config.userInfoUrl || userInfoUrl,
                introspectionUrl: config.introspectionUrl || introspectionUrl,
                
                // Default values
                authFlow: config.authFlow || 'authorization-code',
                requiredScopes: config.requiredScopes || [ 'openid', 'profile' ],
                forceHttps: config.forceHttps !== false, // Default to true for OAuth 2.1 compliance
                requiredRoles: config.requiredRoles || [],
                allowAnonymous: config.allowAnonymous || false
            }
        }
        
        
        return finalConfig
    }


    #setupRouter() {
        // Setup routes for each configured realm
        this.#routeConfigs.forEach( ( config, routePath ) => {
            this.#setupRouteEndpoints( { routePath, config } )
        } )
        
        // Setup global well-known endpoints
        this.#setupGlobalWellKnown()
    }


    #setupRouteEndpoints( { routePath, config } ) {
        // Create HTTPS middleware for this route (defaults to true for OAuth 2.1 compliance)
        const forceHttps = config.forceHttps !== false // Default to true
        const httpsMiddleware = forceHttps 
            ? ( req, res, next ) => {
                if( !this.#isSecureConnection( { req } ) ) {
                    return this.#sendHttpsRequiredError( { res } )
                }
                next()
            }
            : ( req, res, next ) => next()
        
        // OAuth login endpoint per route
        this.#router.get( `${routePath}/auth/login`, httpsMiddleware, ( req, res ) => {
            this.#handleLogin( { req, res, routePath } )
        } )
        
        // OAuth callback endpoint per route (GET and POST for different flows)
        this.#router.get( `${routePath}/auth/callback`, httpsMiddleware, async ( req, res ) => {
            await this.#handleCallback( { req, res, routePath } )
        } )
        this.#router.post( `${routePath}/auth/callback`, httpsMiddleware, async ( req, res ) => {
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
        try {
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
            
            this.#logRouteAccess( { 
                routePath, 
                method: 'LOGIN', 
                status: 'initiated', 
                user: { sub: 'unauthenticated' } 
            } )
            
            res.redirect( authorizationUrl )
        } catch( loginError ) {
            Logger.error( { 
                silent: this.#silent, 
                message: `Login error for ${routePath}: ${loginError.message}` 
            } )
            
            res.status( 500 ).json( {
                error: 'server_error',
                error_description: 'Internal authentication error during login initialization'
            } )
        }
    }


    async #handleCallback( { req, res, routePath } ) {
        const { code, state, error, error_description } = req.query
        const sharedHelpers = this.#routeClients.get( 'shared' )
        
        // Handle OAuth error responses (user denied, etc.)
        if( error ) {
            this.#logRouteAccess( {
                routePath,
                method: 'CALLBACK',
                status: 'error',
                user: { sub: 'unauthenticated' },
                error: error,
                error_description: error_description
            } )
            
            return res.status( 400 ).json( {
                error: error,
                error_description: error_description || 'Authorization failed',
                login_url: `${req.protocol}://${req.get( 'host' )}${routePath}/auth/login`
            } )
        }
        
        // Handle missing code/state for successful flow
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
                
                this.#logRouteAccess( { 
                    routePath: route, 
                    method: 'CALLBACK', 
                    status: 'success', 
                    user: { sub: 'authenticated' } 
                } )
                
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
            Logger.error( { 
                silent: this.#silent, 
                message: `Callback error for ${routePath}: ${callbackError.message}` 
            } )
            
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
                `${config.providerUrl}/realms/${config.realm}`
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
                    href: `${config.providerUrl}/realms/${config.realm}`
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
        try {
            // Use OAuthFlowHandler to get discovery metadata
            const sharedHelpers = this.#routeClients.get( 'shared' )
            const discoveryData = sharedHelpers.oauthFlowHandler.getDiscoveryData()
            
            // Return the discovery metadata as JSON
            res.json( discoveryData )
        } catch( error ) {
            Logger.error( { 
                silent: this.#silent, 
                message: `Authorization server metadata error: ${error.message}` 
            } )
            res.status( 500 ).json( { error: 'Internal server error' } )
        }
    }


    async #handleGlobalJwks( { req, res } ) {
        res.json( { keys: [] } )
    }


    async #handleProtectedRequest( { req, res, next, routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        const sharedHelpers = this.#routeClients.get( 'shared' )
        
        // OAuth 2.1 Security: HTTPS check for this route if required
        if( config.forceHttps && !this.#isSecureConnection( { req } ) ) {
            return this.#sendHttpsRequiredError( { res } )
        }
        
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
        
        // Get the AuthType-specific TokenValidator for this route
        const authHandler = sharedHelpers.authHandlers[routePath]
        let validationResult
        
        // Backwards-compatibility: Try AuthType-specific validator first, fallback to legacy
        if( authHandler && authHandler.tokenValidator && typeof authHandler.tokenValidator.validate === 'function' ) {
            // New AuthType-specific validation
            validationResult = await authHandler.tokenValidator.validate( { token } )
        } else if( sharedHelpers.tokenValidator && typeof sharedHelpers.tokenValidator.validateForRoute === 'function' ) {
            // Legacy validation fallback
            validationResult = await sharedHelpers.tokenValidator.validateForRoute( { token, routePath } )
        } else {
            Logger.error( { 
                silent: this.#silent, 
                message: `No token validator found for route: ${routePath}` 
            } )
            return this.#sendUnauthorized( { res, routePath, reason: 'configuration_error' } )
        }
        
        if( !validationResult.isValid ) {
            this.#logRouteAccess( { 
                routePath, 
                method: req.method, 
                status: 'denied', 
                user: { sub: 'invalid_token' } 
            } )
            return this.#sendUnauthorized( { res, routePath, reason: validationResult.error || 'invalid_token' } )
        }
        
        // Optional: Check audience binding for OAuth-based AuthTypes
        if( authHandler && authHandler.authType && authHandler.authType.includes( 'oauth' ) && validationResult.audienceBinding ) {
            if( !validationResult.audienceBinding.isValidAudience ) {
                this.#logRouteAccess( { 
                    routePath, 
                    method: req.method, 
                    status: 'denied', 
                    user: validationResult.decoded 
                } )
                return this.#sendForbidden( { res, routePath, reason: 'invalid_audience' } )
            }
        }
        
        // Check route-specific roles and scopes
        const authzCheck = this.#checkAuthorization( { decoded: validationResult.decoded, config } )
        if( !authzCheck.allowed ) {
            this.#logRouteAccess( { 
                routePath, 
                method: req.method, 
                status: 'denied', 
                user: validationResult.decoded 
            } )
            return this.#sendForbidden( { res, routePath, reason: authzCheck.reason } )
        }
        
        // Set request context
        req.user = validationResult.decoded
        req.authRealm = config.realm
        req.authRoute = routePath
        req.scopes = validationResult.decoded.scope ? validationResult.decoded.scope.split( ' ' ) : []
        req.roles = validationResult.decoded.realm_access?.roles || []
        
        this.#logRouteAccess( { 
            routePath, 
            method: req.method, 
            status: 'success', 
            user: validationResult.decoded 
        } )
        
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
        if( config.requiredRoles && config.requiredRoles.length > 0 ) {
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
        if( config.requiredScopes && config.requiredScopes.length > 0 ) {
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
        
        // Map internal error codes to user-friendly messages
        let message = reason
        if( reason === 'missing_authorization_header' ) {
            message = 'Authorization header required'
        } else if( reason === 'invalid_token_format' || reason === 'empty_bearer_token' ) {
            message = 'Bearer token required'  
        } else if( reason === 'Invalid bearer token' ) {
            message = 'Invalid bearer token'
        } else if( reason.includes('OAuth 2.1 requires Bearer token format') ) {
            message = 'Bearer token required'
        }

        res.status( 401 ).json( {
            error: 'Unauthorized',
            message: message,
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


    // Display Methods

    #log( message ) {
        Logger.info( { silent: this.#silent, message } )
    }


    #displayRoutesSummary() {
        this.#log( '\n🔐 OAuth Middleware Configuration' )
        this.#log( '═══════════════════════════════════════════════════════════════════════════════' )
        
        const routeCount = this.#routeConfigs.size
        const realmCount = new Set( Array.from( this.#routeConfigs.values() ).map( c => c.realm ) ).size
        
        this.#log( `📊 Summary: ${routeCount} route${routeCount !== 1 ? 's' : ''} configured across ${realmCount} realm${realmCount !== 1 ? 's' : ''}` )
        this.#log( '' )
        
        // Display each route configuration
        let routeIndex = 1
        this.#routeConfigs.forEach( ( config, routePath ) => {
            this.#displayRouteDetails( { config, routePath, index: routeIndex++ } )
        } )
        
        this.#log( '═══════════════════════════════════════════════════════════════════════════════' )
        this.#log( '' )
    }


    #displayRouteDetails( { config, routePath, index } ) {
        // Get base URL from config or use defaults
        const baseUrl = config.resourceUri ? 
            config.resourceUri.replace( routePath, '' ).replace( /\/$/, '' ) : 
            'http://localhost:3000'
        
        this.#log( `📍 Route ${index}: ${routePath}` )
        this.#log( `   ├─ Realm:        ${config.realm}` )
        this.#log( `   ├─ Provider:     ${config.providerUrl}` )
        this.#log( `   ├─ Client ID:    ${config.clientId}` )
        this.#log( `   ├─ Auth Flow:    ${config.authFlow}` )
        
        // Display required scopes
        if( config.requiredScopes && config.requiredScopes.length > 0 ) {
            const scopeList = config.requiredScopes.join( ', ' )
            this.#log( `   ├─ Scopes:       ${scopeList}` )
        }
        
        // Display required roles
        if( config.requiredRoles && config.requiredRoles.length > 0 ) {
            const roleList = config.requiredRoles.join( ', ' )
            this.#log( `   ├─ Roles:        ${roleList}` )
        }
        
        // Display security settings
        const securityFlags = []
        if( config.allowAnonymous ) securityFlags.push( '🟡 Anonymous allowed' )
        if( config.authFlow === 'authorization-code' ) securityFlags.push( '🟢 PKCE required' )
        
        if( securityFlags.length > 0 ) {
            this.#log( `   ├─ Security:     ${securityFlags.join( ', ' )}` )
        }
        
        // Display endpoints with full URLs for clickability
        this.#log( `   ├─ Endpoints:` )
        this.#log( `   │  ├─ Login:     ${baseUrl}${routePath}/auth/login` )
        this.#log( `   │  ├─ Callback:  ${baseUrl}${routePath}/callback` )
        this.#log( `   │  ├─ Discovery: ${baseUrl}${routePath}/discovery` )
        this.#log( `   │  └─ Metadata:  ${baseUrl}/.well-known/oauth-protected-resource${routePath}` )
        this.#log( `   └─ Auth0 Setup:` )
        this.#log( `      ├─ Domain:                   ${config.providerUrl}` )
        this.#log( `      ├─ Client ID:                ${config.clientId}` )
        this.#log( `      ├─ Allowed Callback URLs:    ${baseUrl}${routePath}/auth/callback` )
        this.#log( `      └─ Allowed Web Origins:      ${baseUrl}${routePath}` )
        
        if( index < this.#routeConfigs.size ) {
            this.#log( '' )
        }
    }


    #logRouteAccess( { routePath, method, status, user } ) {
        if( this.#silent ) return
        
        const timestamp = new Date().toISOString()
        const username = user?.preferred_username || user?.sub || 'anonymous'
        const statusIcon = status === 'success' ? '✅' : status === 'denied' ? '❌' : '⚠️'
        
        this.#log( `${statusIcon} [${timestamp}] ${method} ${routePath} - User: ${username} - Status: ${status}` )
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
        
        // For local development, allow localhost only if explicitly enabled
        if( process.env.NODE_ENV === 'development' && process.env.ALLOW_HTTP_LOCALHOST === 'true' ) {
            const host = req.get( 'host' ) || ''
            if( host.includes( 'localhost' ) || host.includes( '127.0.0.1' ) ) {
                Logger.warn( { 
                    silent: this.#silent, 
                    message: 'HTTPS requirement bypassed for local development' 
                } )
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
        
        // OAuth 2.1: Bearer tokens only, no URL parameters (case-insensitive)
        if( !authHeader.toLowerCase().startsWith( 'bearer ' ) ) {
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
        
        // Extract token, handling case-insensitive Bearer prefix
        const bearerMatch = authHeader.match( /^bearer\s+(.*)/i )
        const token = bearerMatch ? bearerMatch[1] : ''
        
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


    // Configuration Mapping and Legacy Compatibility Methods


    getRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    getRealms() {
        const realms = []
        
        this.#routeConfigs.forEach( ( config, routePath ) => {
            const realmData = {
                route: routePath,
                realm: this.#deriveRealmName( { routePath } ),
                providerUrl: config.providerUrl,
                resourceUri: this.#deriveResourceUri( { routePath } )
            }
            
            realms.push( realmData )
        } )
        
        return realms
    }


    getRouteConfig( routePath ) {
        const config = this.#routeConfigs.get( routePath )
        if( !config ) {
            return undefined
        }
        
        // Add legacy compatibility properties
        const configWithRealm = {
            ...config,
            realm: this.#deriveRealmName( { routePath } ),
            resourceUri: this.#deriveResourceUri( { routePath } ),
            requiredScopes: this.#deriveRequiredScopes( { config } )
        }
        
        return configWithRealm
    }


    #deriveRealmName( { routePath } ) {
        // Generate realm name from route path
        if( routePath === '/mcp' ) {
            return 'test-realm'
        } else if( routePath === '/api' ) {
            return 'api-realm'
        } else if( routePath === '/' ) {
            return 'legacy-realm'
        } else {
            // Generate realm name from route path for other routes
            const cleanPath = routePath.replace( /^\//, '' ).replace( /[^a-zA-Z0-9]/g, '-' )
            return `${cleanPath}-realm`
        }
    }


    #deriveResourceUri( { routePath } ) {
        // For testing, return localhost URIs
        // In production, this would be derived from the actual host
        return `http://localhost:3000${routePath}`
    }


    #deriveRequiredScopes( { config } ) {
        if( !config.scope ) {
            return config.requiredScopes || []
        }
        
        // Parse scope string to extract non-OIDC scopes
        const scopes = config.scope.split( ' ' )
        const filteredScopes = scopes.filter( scope => 
            !['openid', 'profile', 'email', 'offline_access'].includes( scope )
        )
        
        return filteredScopes
    }


    getRouteClient( routePath ) {
        return this.#routeClients.get( routePath )
    }


    getRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }




    displayStatus() {
        if( this.#silent ) return
        
        this.#displayRoutesSummary()
    }


    setSilent( { silent } ) {
        this.#silent = silent
    }
}

export { McpAuthMiddleware }