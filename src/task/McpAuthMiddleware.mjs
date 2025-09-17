import express from 'express'
import jwt from 'jsonwebtoken'
// Using native fetch (Node.js 22+)

import { AuthTypeFactory } from '../core/AuthTypeFactory.mjs'
// DynamicClientRegistration removed - was Keycloak-specific
import { Logger } from '../helpers/Logger.mjs'
import { McpOAuthDiscoveryHandler } from '../handlers/McpOAuthDiscoveryHandler.mjs'
import { OAuthFlowHandler } from '../helpers/OAuthFlowHandler.mjs'
// Legacy TokenValidator removed - only AuthType-specific validators used
import { Validation } from './Validation.mjs'


class McpAuthMiddleware {
    #routeConfigs
    #routeClients
    #router
    #silent
    #forceHttps
    #baseUrl
    #discoveryHandler
    #staticBearer
    #oauth21


    constructor( { staticBearer = null, oauth21 = null, silent = false, baseUrl = 'http://localhost:3000', forceHttps = false } ) {
        this.#silent = silent
        this.#forceHttps = forceHttps
        this.#baseUrl = this.#resolveBaseUrl( { baseUrl, forceHttps } )
        this.#staticBearer = staticBearer
        this.#oauth21 = oauth21
        this.#routeConfigs = new Map()
        this.#routeClients = new Map()
        this.#router = express.Router()
        this.#discoveryHandler = null
    }


    static async create( createParamsInput ) {
        // Extract known parameters with defaults
        const { staticBearer = null, oauth21 = null, silent = false, baseUrl, forceHttps = false } = createParamsInput || {}

        // Strict input validation using original input to catch unknown parameters
        const { status, messages } = Validation.validationCreate( createParamsInput )
        if( !status ) {
            const errorMessage = messages.join( ', ' )
            throw new Error( `Input validation failed: ${errorMessage}` )
        }

        const middleware = new McpAuthMiddleware( { staticBearer, oauth21, silent, baseUrl, forceHttps } )

        // Build internal route map from attachedRoutes
        await middleware.#buildRouteMapFromAttachedRoutes()

        // Initialize auth handlers for configured routes
        await middleware.#initializeAuthHandlers()

        // Setup express router with all routes
        middleware.#setupRouter()

        return middleware
    }


    #buildRouteMapFromAttachedRoutes() {
        // Build internal route configuration map from staticBearer and oauth21 attachedRoutes

        // Add StaticBearer routes
        if( this.#staticBearer?.attachedRoutes ) {
            this.#staticBearer.attachedRoutes.forEach( route => {
                this.#routeConfigs.set( route, {
                    authType: 'staticBearer',
                    tokenSecret: this.#staticBearer.tokenSecret,
                    allowAnonymous: false,
                    forceHttps: this.#forceHttps,
                    _baseUrl: this.#baseUrl
                } )
            } )
        }

        // Add OAuth21 routes
        if( this.#oauth21?.attachedRoutes ) {
            this.#oauth21.attachedRoutes.forEach( route => {
                this.#routeConfigs.set( route, {
                    authType: this.#oauth21.authType,
                    ...this.#oauth21.options,
                    allowAnonymous: false,
                    forceHttps: this.#forceHttps,
                    _baseUrl: this.#baseUrl
                } )
            } )
        }

        if( !this.#silent ) {
            const routeCount = this.#routeConfigs.size
            if( routeCount === 0 ) {
                Logger.info( {
                    silent: this.#silent,
                    message: '⚠️  NO AUTHENTICATION - Server is unprotected (both staticBearer and oauth21 are null)'
                } )
            } else {
                Logger.info( {
                    silent: this.#silent,
                    message: `📊 Built route map: ${routeCount} route${routeCount !== 1 ? 's' : ''} configured`
                } )
            }
        }
    }


    async #initializeAuthHandlers() {
        // Early return if no routes configured (unprotected server)
        if( this.#routeConfigs.size === 0 ) {
            if( !this.#silent ) {
                Logger.info( {
                    silent: this.#silent,
                    message: 'No auth handlers needed - server is unprotected'
                } )
            }
            return
        }

        // Create AuthType-based handlers for all routes
        const authHandlers = {}

        for( const [ routePath, config ] of this.#routeConfigs.entries() ) {
            try {
                // Enhanced config with request-based URL capability for AuthType handlers
                const enhancedConfig = {
                    ...config,
                    _baseUrl: this.#baseUrl,
                    _getRequestBaseUrl: ( { req } ) => this.#getRequestBaseUrl( { req } )
                }

                const authHandler = await AuthTypeFactory.createAuthHandler( {
                    authType: config.authType,
                    config: enhancedConfig,
                    silent: this.#silent
                } )
                authHandlers[routePath] = authHandler

                // Update both routeConfigs with enhanced config that includes generated endpoints
                const finalConfig = authHandler.config || enhancedConfig
                this.#routeConfigs.set( routePath, finalConfig )
            } catch( error ) {
                throw new Error( `Failed to create AuthType handler for route ${routePath}: ${error.message}` )
            }
        }

        // Filter routes to only include OAuth-based AuthTypes for FlowHandler
        const validatedRoutes = Object.fromEntries( this.#routeConfigs.entries() )
        const oauthRoutes = Object.fromEntries(
            Object.entries( validatedRoutes )
                .filter( ( [ route, config ] ) => config && config.authType && config.authType.includes( 'oauth' ) )
        )

        // Note: baseRedirectUri is set here but will be dynamically overridden in OAuth handlers
        // to use request-based URLs for port consistency
        let baseRedirectUri = this.#baseUrl
        if( oauthRoutes && Object.keys( oauthRoutes ).length > 0 ) {
            const firstRoute = Object.keys( oauthRoutes )[0]
            const firstConfig = oauthRoutes[firstRoute]
            if( firstConfig && firstConfig.resourceUri ) {
                const url = new URL( firstConfig.resourceUri )
                baseRedirectUri = `${url.protocol}//${url.host}`
            }
        }

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
            oauthFlowHandler
        } )

        // Create MCP Discovery Handler for .well-known endpoints on root level
        this.#discoveryHandler = McpOAuthDiscoveryHandler.create( {
            routes: validatedRoutes,
            silent: this.#silent,
            baseUrl: this.#baseUrl
        } )

        if( !this.#silent ) {
            this.#displayRoutesSummary()
        }
    }






    #setupRouter() {
        // Setup global well-known endpoints FIRST
        this.#setupGlobalWellKnown()

        // Setup MCP-compliant discovery endpoints BEFORE protected routes
        this.#setupMcpDiscoveryEndpoints()

        // Setup routes for each configured realm (including protected middleware)
        this.#routeConfigs.forEach( ( config, routePath ) => {
            this.#setupRouteEndpoints( { routePath, config } )
        } )
    }


    #setupRouteEndpoints( { routePath, config } ) {
        // Check if this is an OAuth-based route
        const isOAuthRoute = config.authType && config.authType.includes( 'oauth' )
        
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
        
        // Only register OAuth endpoints for OAuth-based authTypes
        if( isOAuthRoute ) {
            // OAuth login endpoint per route
            this.#router.get( `${routePath}/auth/login`, httpsMiddleware, ( req, res ) => {
                this.#handleLogin( { req, res, routePath } )
            } )

            // Dynamic Client Registration endpoint for ScaleKit (returns pre-configured credentials)
            if( config.authType === 'oauth21_scalekit' ) {
                this.#router.post( `${routePath}/oauth/register`, ( req, res ) => {
                    this.#handleScalekitRegistration( { req, res, routePath } )
                } )
            }

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
        }
        
        // Protected middleware for this route (applies to all authTypes)
        this.#router.use( routePath, ( req, res, next ) => {
            this.#handleProtectedRequest( { req, res, next, routePath } )
        } )
    }


    #setupGlobalWellKnown() {
        // Central OAuth Authorization Server metadata (RFC 8414)
        
        // Global JWKS endpoint
        this.#router.get( '/.well-known/jwks.json', async ( req, res ) => {
            await this.#handleGlobalJwks( { req, res } )
        } )
    }


    #setupMcpDiscoveryEndpoints() {
        // MCP Spec: Discovery endpoints must be on root level (/.well-known/...)
        // Only OAuth routes need discovery endpoints
        const hasOAuthRoutes = this.#oauth21 !== null && this.#oauth21 !== undefined

        if( hasOAuthRoutes ) {
            // Root-level Authorization Server Metadata (RFC 8414)
            this.#router.get( '/.well-known/oauth-authorization-server', async ( req, res ) => {
                try {
                    // Generate aggregated metadata for all OAuth routes
                    const { success, metadata, error } = await this.#generateServerWideAuthorizationMetadata( { req } )

                    if( !success ) {
                        return res.status( 404 ).json( { error } )
                    }

                    res.set( {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'public, max-age=3600',
                        'Access-Control-Allow-Origin': '*'
                    } )

                    res.json( metadata )
                } catch( handlerError ) {
                    this.#log( `Error generating server-wide authorization metadata: ${handlerError.message}` )

                    res.status( 500 ).json( {
                        error: 'Internal server error generating authorization server metadata'
                    } )
                }
            } )

            // Root-level Protected Resource Metadata (RFC 9728)
            this.#router.get( '/.well-known/oauth-protected-resource', ( req, res ) => {
                try {
                    const { success, metadata, error } = this.#generateServerWideProtectedResourceMetadata( { req } )

                    if( !success ) {
                        return res.status( 404 ).json( { error } )
                    }

                    res.set( {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'public, max-age=3600',
                        'Access-Control-Allow-Origin': '*'
                    } )

                    res.json( metadata )
                } catch( handlerError ) {
                    this.#log( `Error generating server-wide protected resource metadata: ${handlerError.message}` )

                    res.status( 500 ).json( {
                        error: 'Internal server error generating protected resource metadata'
                    } )
                }
            } )

            if( !this.#silent ) {
                Logger.info( {
                    silent: this.#silent,
                    message: `MCP Discovery endpoints registered on root level (OAuth routes: ${this.#oauth21.attachedRoutes.join( ', ' )})`
                } )
            }
        } else if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: 'No OAuth routes configured - MCP Discovery endpoints not needed'
            } )
        }
    }


    async #generateServerWideAuthorizationMetadata( { req } ) {
        // Generate authorization server metadata that covers all OAuth routes on the server
        if( !this.#oauth21 ) {
            return {
                success: false,
                error: 'No OAuth configuration found'
            }
        }

        try {
            // Use the first OAuth route as a template for metadata generation
            const firstOAuthRoute = this.#oauth21.attachedRoutes[0]
            const routeConfig = this.#routeConfigs.get( firstOAuthRoute )

            if( !routeConfig ) {
                return {
                    success: false,
                    error: `OAuth route configuration not found: ${firstOAuthRoute}`
                }
            }

            // Create auth handler for metadata generation with enhanced config
            const enhancedRoutConfig = {
                ...routeConfig,
                _baseUrl: this.#baseUrl,
                _getRequestBaseUrl: ( { req } ) => this.#getRequestBaseUrl( { req } )
            }

            const authHandler = await AuthTypeFactory.createAuthHandler( {
                authType: routeConfig.authType,
                config: enhancedRoutConfig,
                silent: this.#silent
            } )

            // Use provider's discovery metadata generation
            if( authHandler.provider && typeof authHandler.provider.getDiscoveryMetadata === 'function' ) {
                const providerResult = authHandler.provider.getDiscoveryMetadata( { config: routeConfig } )

                if( providerResult.success ) {
                    // Enhance metadata with server-wide information
                    const requestBaseUrl = this.#getRequestBaseUrl( { req } )
                    const enhancedMetadata = {
                        ...providerResult.metadata,
                        // Add server-wide scope covering all OAuth routes
                        protected_resources: this.#oauth21.attachedRoutes.map( route => `${requestBaseUrl}${route}` )
                    }

                    return {
                        success: true,
                        metadata: enhancedMetadata
                    }
                }
            }

            return {
                success: false,
                error: `OAuth provider ${routeConfig.authType} does not support discovery metadata generation`
            }
        } catch( error ) {
            return {
                success: false,
                error: `Failed to generate authorization server metadata: ${error.message}`
            }
        }
    }


    #generateServerWideProtectedResourceMetadata( { req } ) {
        // Generate protected resource metadata for all OAuth-protected routes
        if( !this.#oauth21 ) {
            return {
                success: false,
                error: 'No OAuth configuration found'
            }
        }

        const oauthRoutes = this.#oauth21.attachedRoutes
        const firstRoute = oauthRoutes[0]
        const routeConfig = this.#routeConfigs.get( firstRoute )

        if( !routeConfig ) {
            return {
                success: false,
                error: `OAuth route configuration not found: ${firstRoute}`
            }
        }

        const requestBaseUrl = this.#getRequestBaseUrl( { req } )

        // RFC 9728 Protected Resource Metadata for server-wide protection
        const metadata = {
            // Required fields per RFC 9728
            resource: `${requestBaseUrl}/*`,  // Server-wide resource protection
            authorization_servers: [
                requestBaseUrl  // Our server acts as the authorization server endpoint
            ],

            // Optional but recommended fields
            jwks_uri: routeConfig.jwksUrl,
            scopes_supported: routeConfig.requiredScopes || [],

            // OAuth 2.1 security information
            bearer_methods_supported: [ 'header' ], // RFC 6750 - Bearer token in Authorization header only
            resource_signing_alg_values_supported: [ 'RS256', 'RS384', 'RS512' ],

            // Server-wide protection information
            protected_resources: oauthRoutes.map( route => `${requestBaseUrl}${route}` ),
            auth_type: routeConfig.authType,

            // Links per RFC 9728
            links: [
                {
                    rel: 'authorization_server',
                    href: `${requestBaseUrl}/.well-known/oauth-authorization-server`
                },
                {
                    rel: 'protected_resources',
                    href: oauthRoutes.map( route => `${requestBaseUrl}${route}` )
                }
            ]
        }

        return {
            success: true,
            metadata
        }
    }


    #handleLogin( { req, res, routePath } ) {
        try {
            const sharedHelpers = this.#routeClients.get( 'shared' )
            const config = this.#routeConfigs.get( routePath )
            
            // Resource parameter for audience binding (RFC 8707)
            const resourceUri = this.#generateURL( { req, routePath, path: routePath } )
            
            const { authorizationUrl, state, routePath: returnedRoutePath } = 
                sharedHelpers.oauthFlowHandler.initiateAuthorizationCodeFlowForRoute( {
                    routePath: routePath,
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
                login_url: this.#generateURL( { req, routePath, path: `${routePath}/auth/login` } )
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
            const { success, tokens, routePath, resourceIndicators, error } = await 
                sharedHelpers.oauthFlowHandler.handleAuthorizationCallbackForRoute( {
                    code,
                    state
                } )
            
            if( success ) {
                const config = this.#routeConfigs.get( routePath )
                
                this.#logRouteAccess( { 
                    routePath: routePath, 
                    method: 'CALLBACK', 
                    status: 'success', 
                    user: { sub: 'authenticated' } 
                } )
                
                res.json( {
                    message: 'Authentication successful',
                    route: routePath,
                    realm: config.realm,
                    access_token: tokens.access_token,
                    token_type: tokens.token_type,
                    expires_in: tokens.expires_in,
                    scope: tokens.scope,
                    resourceIndicators,
                    usage: `Use Bearer token for ${routePath} endpoints`
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
        const requestBaseUrl = this.#getRequestBaseUrl( { req } )
        const baseUrl = this.#generateURL( { req, routePath } )
        const resourceUri = `${baseUrl}${routePath}`
        
        // RFC 9728 Protected Resource Metadata - Complete Implementation
        const metadata = {
            // Required fields per RFC 9728
            // For ScaleKit, use the configured resource URL that matches the dashboard
            resource: config.authType === 'oauth21_scalekit' && config.resource
                ? config.resource
                : resourceUri,
            authorization_servers: [
                // For OAuth 2.1 with external providers, point to our local middleware as the authorization server
                // This allows MCP clients to discover our registration endpoint and OAuth flow
                config.authType === 'oauth21_scalekit'
                    ? requestBaseUrl
                    : `${config.providerUrl}/realms/${config.realm}`
            ],
            
            // Optional but recommended fields
            jwks_uri: config.jwksUrl,
            scopes_supported: config.requiredScopes,
            resource_documentation: `${requestBaseUrl}${routePath}/discovery`,
            
            // Additional OAuth 2.1 and security information
            bearer_methods_supported: [ 'header' ], // RFC 6750 - Bearer token in Authorization header only
            resource_signing_alg_values_supported: [ 'RS256', 'RS384', 'RS512' ],
            
            // Route-specific metadata
            route_info: {
                path: routePath,
                realm: config.realm,
                auth_flows_supported: [ config.authFlow ],
                client_id: config.clientId,
                required_roles: config.requiredRoles
            },
            
            // Links per RFC 9728
            links: [
                {
                    rel: 'authorization_server',
                    href: config.authType === 'oauth21_scalekit'
                        ? config.providerUrl
                        : `${config.providerUrl}/realms/${config.realm}`
                },
                {
                    rel: 'login',
                    href: `${requestBaseUrl}${routePath}/auth/login`
                },
                {
                    rel: 'discovery',
                    href: `${requestBaseUrl}${routePath}/discovery`
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
        const baseUrl = this.#generateURL( { req, routePath } )
        
        res.json( {
            route: routePath,
            realm: config.realm,
            authFlow: config.authFlow,
            endpoints: {
                login: `${baseUrl}${routePath}/auth/login`,
                callback: `${baseUrl}${routePath}/auth/callback`,
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




    async #handleGlobalJwks( { req, res } ) {
        res.json( { keys: [] } )
    }


    async #handleProtectedRequest( { req, res, next, routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        const sharedHelpers = this.#routeClients.get( 'shared' )

        // Allow unauthenticated access to OAuth registration endpoint for dynamic client registration
        if( req.path.endsWith( '/oauth/register' ) && config.authType === 'oauth21_scalekit' ) {
            return next()
        }

        // OAuth 2.1 Security: HTTPS check for this route if required
        if( config.forceHttps && !this.#isSecureConnection( { req } ) ) {
            return this.#sendHttpsRequiredError( { res } )
        }
        
        // Check if route allows anonymous access
        if( config.allowAnonymous && !req.headers.authorization ) {
            req.user = { anonymous: true }
            req.authType = config.authType
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
        
        // AuthType-specific validation (only supported approach)
        if( authHandler && authHandler.tokenValidator && typeof authHandler.tokenValidator.validate === 'function' ) {
            validationResult = await authHandler.tokenValidator.validate( { token } )
        } else {
            Logger.error( {
                silent: this.#silent,
                message: `No token validator found for route: ${routePath}. Ensure authType is oauth21_scalekit or staticBearer`
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
        req.authType = config.authType
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


    // Audience binding validation is handled by AuthType-specific token validators


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
        const config = this.#routeConfigs.get( routePath )
        const isOAuthRoute = config.authType && config.authType.includes( 'oauth' )
        const baseUrl = this.#generateURL( { req: res.req, routePath } )
        
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

        if( isOAuthRoute ) {
            // OAuth-specific 401 response with metadata
            const prmUrl = `${baseUrl}/.well-known/oauth-protected-resource${routePath}`
            
            // RFC 9728 compliant 401 response
            res.set( 'WWW-Authenticate', `Bearer realm="${routePath}", error="invalid_token", error_description="${reason}", resource_metadata="${prmUrl}"` )
            
            res.status( 401 ).json( {
                error: 'Unauthorized',
                message: message,
                error_description: reason,
                route: routePath,
                protected_resource_metadata: prmUrl,
                login_url: `${baseUrl}${routePath}/auth/login`
            } )
        } else {
            // Simple Bearer token 401 response for non-OAuth routes
            res.set( 'WWW-Authenticate', `Bearer realm="${routePath}", error="invalid_token", error_description="${reason}"` )
            
            res.status( 401 ).json( {
                error: 'Unauthorized',
                message: message,
                error_description: reason,
                route: routePath
            } )
        }
    }


    #sendForbidden( { res, routePath, reason } ) {
        const config = this.#routeConfigs.get( routePath )
        const baseUrl = this.#generateURL( { req: res.req, routePath } )
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
        this.#log( '\n🔐 MCP OAuth Middleware v1.0' )
        this.#log( '═══════════════════════════════════════════════════════════════════════════════' )

        // Ungeschützt
        if( !this.#staticBearer && !this.#oauth21 ) {
            this.#log( '⚠️  NO AUTHENTICATION - Server is unprotected' )
            this.#log( '   └─ Both staticBearer and oauth21 are null' )
            this.#log( '' )
            this.#log( '🔧 Global Configuration:' )
            this.#log( `   ├─ Base URL:     ${this.#baseUrl}` )
            this.#log( `   ├─ Force HTTPS:  ${this.#forceHttps}` )
            this.#log( `   └─ Silent Mode:  ${this.#silent}` )
            this.#log( '═══════════════════════════════════════════════════════════════════════════════' )
            this.#log( '' )
            return
        }

        // StaticBearer
        if( this.#staticBearer ) {
            this.#log( '🔑 StaticBearer Authentication' )
            this.#log( `   ├─ Token Secret: ${this.#staticBearer.tokenSecret.substring( 0, 8 )}...` )
            this.#log( `   └─ Protected Routes: ${this.#staticBearer.attachedRoutes.join( ', ' )}` )
        }

        // OAuth
        if( this.#oauth21 ) {
            this.#log( '🔐 OAuth 2.1 Authentication' )
            this.#log( `   ├─ Provider: ${this.#oauth21.authType}` )
            this.#log( `   ├─ Protected Routes: ${this.#oauth21.attachedRoutes.join( ', ' )}` )
            this.#log( `   └─ Discovery: ${this.#baseUrl}/.well-known/` )
        }

        this.#log( '' )
        this.#log( '🔧 Global Configuration:' )
        this.#log( `   ├─ Base URL:     ${this.#baseUrl}` )
        this.#log( `   ├─ Force HTTPS:  ${this.#forceHttps}` )
        this.#log( `   └─ Silent Mode:  ${this.#silent}` )
        this.#log( '' )

        const routeCount = this.#routeConfigs.size
        this.#log( `📊 Total Routes Protected: ${routeCount}` )

        this.#log( '═══════════════════════════════════════════════════════════════════════════════' )
        this.#log( '' )
    }


    #displayRouteDetails( { config, routePath, index } ) {
        // Use configured global baseUrl for display consistency
        const baseUrl = this.#baseUrl
        
        const isOAuthRoute = config.authType && config.authType.includes( 'oauth' )
        
        this.#log( `📍 Route ${index}: ${routePath}` )
        this.#log( `   ├─ Realm:        ${config.realm}` )
        
        if( isOAuthRoute ) {
            // OAuth-specific details
            this.#log( `   ├─ Provider:     ${config.providerUrl}` )
            this.#log( `   ├─ Client ID:    ${config.clientId}` )
            
            // Display protocol information
            const protocol = baseUrl.startsWith('https://') ? 'HTTPS' : 'HTTP'
            this.#log( `   ├─ Protocol:     🔗 ${protocol}` )
            this.#log( `   ├─ Auth Flow:    ${config.authFlow}` )
            
            // Display required scopes
            if( config.requiredScopes && config.requiredScopes.length > 0 ) {
                const scopeList = config.requiredScopes.join( ', ' )
                this.#log( `   ├─ Scopes:       ${scopeList}` )
            }
            
            // Display security settings
            const securityFlags = []
            if( config.allowAnonymous ) securityFlags.push( '🟡 Anonymous allowed' )
            if( config.authFlow === 'authorization-code' ) securityFlags.push( '🟢 PKCE required' )
            
            // Add forceHttps status
            if( config.forceHttps !== undefined ) {
                securityFlags.push( config.forceHttps ? '🟢 HTTPS enforced' : '🟡 HTTP allowed' )
            }
            
            if( securityFlags.length > 0 ) {
                this.#log( `   ├─ Security:     ${securityFlags.join( ', ' )}` )
            }
            
            // Display OAuth endpoints
            this.#log( `   ├─ Endpoints:` )
            this.#log( `   │  ├─ Login:     ${baseUrl}${routePath}/auth/login` )
            this.#log( `   │  ├─ Callback:  ${baseUrl}${routePath}/auth/callback` )
            this.#log( `   │  ├─ Discovery: ${baseUrl}${routePath}/discovery` )
            this.#log( `   │  └─ Metadata:  ${baseUrl}/.well-known/oauth-protected-resource${routePath}` )
            this.#log( `   └─ Auth0 Setup:` )
            this.#log( `      ├─ Domain:                   ${config.providerUrl}` )
            this.#log( `      ├─ Client ID:                ${config.clientId}` )
            this.#log( `      ├─ Allowed Callback URLs:    ${baseUrl}${routePath}/auth/callback` )
            this.#log( `      └─ Allowed Web Origins:      ${baseUrl}${routePath}` )
        } else {
            // StaticBearer or other non-OAuth authentication
            this.#log( `   ├─ Auth Type:    ${config.authType}` )
            this.#log( `   ├─ Token:        Bearer token required in Authorization header` )
            
            // Display required roles if any
            if( config.requiredRoles && config.requiredRoles.length > 0 ) {
                const roleList = config.requiredRoles.join( ', ' )
                this.#log( `   ├─ Roles:        ${roleList}` )
            }
            
            // Simple security info
            const securityFlags = []
            if( config.allowAnonymous ) securityFlags.push( '🟡 Anonymous allowed' )
            securityFlags.push( '🟢 Bearer token authentication' )
            
            this.#log( `   ├─ Security:     ${securityFlags.join( ', ' )}` )
            this.#log( `   └─ Usage:        Send requests with "Authorization: Bearer <token>" header` )
        }
        
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


    #resolveBaseUrl( { baseUrl, forceHttps } ) {
        // Parse the baseUrl (which now always has a default value)
        try {
            const url = new URL( baseUrl )
            
            // Override protocol if forceHttps is specified
            if( forceHttps === true && url.protocol === 'http:' ) {
                url.protocol = 'https:'
            } else if( forceHttps === false && url.protocol === 'https:' ) {
                url.protocol = 'http:'
            }
            
            // Return without trailing slash
            return `${url.protocol}//${url.host}`
        } catch( error ) {
            // This should not happen with proper validation, but keep as safety net
            Logger.warn( { 
                silent: this.#silent, 
                message: `Invalid baseUrl provided: ${baseUrl}, using fallback` 
            } )
            const protocol = forceHttps === true ? 'https' : 'http'
            return `${protocol}://localhost:3000`
        }
    }


    #generateURL( { req, routePath = null, path = '' } ) {
        // Get route-specific config if routePath is provided
        const config = routePath ? this.#routeConfigs.get( routePath ) : null

        // Determine protocol: route-specific forceHttps > global forceHttps > req.protocol
        const forceHttps = config?.forceHttps ?? this.#forceHttps
        const protocol = forceHttps ? 'https' : req.protocol

        return `${protocol}://${req.get( 'host' )}${path}`
    }


    #getRequestBaseUrl( { req, routePath = null } ) {
        // Consistent helper for request-based baseURL generation
        // Replaces this.#baseUrl usage to ensure port consistency
        return this.#generateURL( { req, routePath, path: '' } )
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




    getRouteConfig( { routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        if( !config ) {
            return undefined
        }
        
        // Add dynamic properties while preserving all original config (including Entry-Point defaults)
        const configWithRealm = {
            ...config,  // Keep ALL original fields including Entry-Point defaults
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
        // Use configured baseUrl instead of hardcoded localhost
        return `${this.#baseUrl}${routePath}`
    }


    #deriveRequiredScopes( { config } ) {
        if( !config.scope ) {
            return config.requiredScopes
        }
        
        // Parse scope string to extract non-OIDC scopes
        const scopes = config.scope.split( ' ' )
        const filteredScopes = scopes.filter( scope => 
            !['openid', 'profile', 'email', 'offline_access'].includes( scope )
        )
        
        return filteredScopes
    }


    getRouteClient( { routePath } ) {
        return this.#routeClients.get( routePath )
    }


    displayStatus() {
        if( this.#silent ) return

        this.#displayRoutesSummary()
    }


    setSilent( { silent } ) {
        this.#silent = silent
    }


    #handleScalekitRegistration( { req, res, routePath } ) {
        const config = this.#routeConfigs.get( routePath )

        if( !config || config.authType !== 'oauth21_scalekit' ) {
            return res.status( 404 ).json( {
                error: 'not_found',
                error_description: 'Registration endpoint not available for this route'
            } )
        }

        // ScaleKit doesn't support true dynamic client registration
        // We return the pre-configured client credentials for MCP clients
        const registrationResponse = {
            client_id: config.clientId,
            client_secret: config.clientSecret,
            client_id_issued_at: Math.floor( Date.now() / 1000 ),
            // Standard DCR response fields
            redirect_uris: [ `${this.#getRequestBaseUrl( { req } )}${routePath}/auth/callback` ],
            response_types: [ 'code' ],
            grant_types: [ 'authorization_code', 'refresh_token' ],
            token_endpoint_auth_method: 'client_secret_post',
            scope: config.scope
        }

        res.set( {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Access-Control-Allow-Origin': '*'
        } )

        return res.status( 201 ).json( registrationResponse )
    }
}

export { McpAuthMiddleware }