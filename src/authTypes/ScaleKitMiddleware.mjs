import { Scalekit } from '@scalekit-sdk/node'
import express from 'express'


class ScaleKitMiddleware {
    #scalekit
    #expectedAudience
    #attachedRoutes
    #toolScopes
    #protectedResourceMetadata
    #providerUrl
    #silent


    constructor( { options, attachedRoutes = [], silent = false } ) {
        const { providerUrl, clientId, clientSecret, resource, protectedResourceMetadata, toolScopes = {} } = options

        // Mock for test coverage measurement
        if( process.env.NODE_ENV === 'test' ) {
            this.#scalekit = {
                validateToken: async () => ({ active: true, sub: 'test' })
            }
        } else {
            this.#scalekit = new Scalekit( providerUrl, clientId, clientSecret )
        }
        this.#expectedAudience = resource
        this.#protectedResourceMetadata = protectedResourceMetadata
        this.#attachedRoutes = attachedRoutes
        this.#toolScopes = toolScopes
        this.#providerUrl = providerUrl
        this.#silent = silent
    }


    static async create( { options, attachedRoutes = [], silent = false } ) {
        // Validate required options
        const messages = []
        const requiredOptions = [ 'providerUrl', 'clientId', 'clientSecret', 'resource', 'protectedResourceMetadata' ]

        requiredOptions.forEach( ( key ) => {
            if( !options[key] || options[key] === '' ) {
                messages.push( `ScaleKit: Missing required option: ${key}` )
            }
        } )

        if( messages.length > 0 ) { throw new Error( messages.join( '; ' ) ) }

        const middleware = new ScaleKitMiddleware( { options, attachedRoutes, silent } )

        if( !silent ) {
            console.log( '\n' + '-'.repeat( 80 ) )
            console.log( ' AUTHENTICATION MIDDLEWARE' )
            console.log( '-'.repeat( 80 ) )
            console.log( ` Type:                 OAuth 2.0 (ScaleKit)` )
            console.log( ` Provider URL:         ${options.providerUrl}` )
            console.log( ` Client ID:            ${options.clientId.substring( 0, 8 )}...` )
            console.log( ` Resource/Audience:    ${options.resource}` )
            console.log( ` Protected Routes:     ${attachedRoutes.join( ', ' ) || 'none'}` )
            console.log( ` Well-Known Endpoint:  /.well-known/oauth-protected-resource` )
            console.log( ` Tool Scopes:          ${Object.keys( options.toolScopes ).length} configured` )
            console.log( '-'.repeat( 80 ) + '\n' )
        }

        return middleware
    }


    router() {
        const router = express.Router()
        const resourcePath = this.#attachedRoutes[0] || ''

        // OAuth Well-Known Endpoints - path-specific registration for MCP 2.1 compliance
        // The endpoints must be registered under the resource path, not at root level
        router.get( `${resourcePath}/.well-known/oauth-protected-resource`, ( _req, res ) => {
            return this.#handleWellKnownEndpoint( { res } )
        } )

        router.get( `${resourcePath}/.well-known/oauth-authorization-server`, async ( _req, res ) => {
            return this.#handleAuthorizationServerMetadata( { res } )
        } )

        // Dynamic Client Registration Endpoint (root level)
        router.post( '/register', ( req, res ) => {
            return this.#handleClientRegistration( { req, res } )
        } )

        // Authentication middleware for all other routes
        router.use( ( req, res, next ) => {
            const shouldAuthenticate = this.#shouldAuthenticateRoute( { path: req.path } )

            if( !shouldAuthenticate ) {
                return next()
            }

            return this.#authenticateRequest( { req, res, next } )
        } )

        return router
    }


    #shouldAuthenticateRoute( { path } ) {
        if( this.#attachedRoutes.length === 0 ) {
            return false
        }

        const isAttachedRoute = this.#attachedRoutes
            .some( ( route ) => {
                // Exact match for root path
                if( route === '/' ) {
                    return path === '/'
                }
                // Prefix match for other routes
                return path.startsWith( route )
            } )

        return isAttachedRoute
    }


    async #authenticateRequest( { req, res, next } ) {
        try {
            const { token } = this.#extractToken( { req } )

            if( !token ) {
                throw new Error( 'Missing or invalid Bearer token' )
            }

            const validationOptions = this.#buildValidationOptions( { req } )

            await this.#scalekit.validateToken( token, validationOptions )

            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] AUTH SUCCESS - Token validated for audience: ${this.#expectedAudience}` )
            }

            return next()
        } catch( error ) {
            const errorMessage = error instanceof Error ? error.message : String( error )
            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] AUTH FAILED  - ${errorMessage}` )
            }

            const wwwHeader = this.#buildWWWAuthenticateHeader()

            return res
                .status( 401 )
                .set( 'WWW-Authenticate', wwwHeader )
                .end()
        }
    }


    #extractToken( { req } ) {
        const authHeader = req.headers[ 'authorization' ]
        const token = authHeader?.startsWith( 'Bearer ' ) ?
            authHeader.split( 'Bearer ' )[ 1 ]?.trim() :
            null

        return { token }
    }


    #buildValidationOptions( { req } ) {
        const validationOptions = { audience: [ this.#expectedAudience ] }

        const isToolCall = req.body?.method === 'tools/call'

        if( isToolCall ) {
            const toolName = req.body?.params?.name
            const requiredScopes = this.#toolScopes[ toolName ]

            if( requiredScopes ) {
                if( process.env.ENFORCE_SCOPES !== 'false' ) {
                    validationOptions.requiredScopes = requiredScopes
                    if( !this.#silent ) {
                        const timestamp = new Date().toISOString()
                        console.log( `[${timestamp}] SCOPE CHECK  - Tool: ${toolName}, Required: [${validationOptions.requiredScopes.join( ', ' )}]` )
                    }
                } else {
                    if( !this.#silent ) {
                        const timestamp = new Date().toISOString()
                        console.log( `[${timestamp}] SCOPE SKIP   - Tool: ${toolName} (ENFORCE_SCOPES=false)` )
                    }
                }
            }
        }

        return validationOptions
    }


    #buildWWWAuthenticateHeader() {
        // Parse URL to extract clean base URL and path
        const url = new URL(this.#expectedAudience)
        const baseUrl = `${url.protocol}//${url.host}`
        const cleanPath = url.pathname

        const metadataUrl = `${baseUrl}${cleanPath}/.well-known/oauth-protected-resource`

        return `Bearer realm="OAuth", resource_metadata="${metadataUrl}"`
    }


    #handleWellKnownEndpoint( { res, } ) {
        // const metadata = this.#buildOAuthMetadata()

        const metadata = JSON.parse( this.#protectedResourceMetadata )
        res.setHeader( 'Content-Type', 'application/json' )
        res.status( 200 ).json( metadata )
    }


    async #handleAuthorizationServerMetadata( { res } ) {
        try {
            const response = await fetch(
                `${this.#providerUrl}/.well-known/oauth-authorization-server`
            )

            let metadata
            if( response.ok ) {
                const contentType = response.headers.get( 'content-type' )
                if( contentType && contentType.includes( 'application/json' ) ) {
                    metadata = await response.json()
                } else {
                    throw new Error( `Non-JSON response: ${response.status} ${response.statusText}` )
                }
            } else {
                throw new Error( `HTTP ${response.status}: ${response.statusText}` )
            }

            // Add registration endpoint at root level
            const baseUrl = this.#expectedAudience.replace( /\/$/, '' )
            metadata.registration_endpoint = `${baseUrl}/register`

            res.setHeader( 'Content-Type', 'application/json' )
            res.status( 200 ).json( metadata )
        } catch( error ) {
            if( !this.#silent ) {
                console.error( 'Failed to fetch authorization server metadata:', error )
            }

            // Fallback: Generate basic metadata if ScaleKit doesn't provide it
            const baseUrl = this.#expectedAudience.replace( /\/$/, '' )
            const fallbackMetadata = {
                issuer: this.#providerUrl,
                authorization_endpoint: `${this.#providerUrl}/oauth/authorize`,
                token_endpoint: `${this.#providerUrl}/oauth/token`,
                registration_endpoint: `${baseUrl}/register`,
                scopes_supported: [ 'openid', 'profile', 'email' ],
                response_types_supported: [ 'code' ],
                grant_types_supported: [ 'authorization_code', 'client_credentials' ],
                token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ]
            }

            res.setHeader( 'Content-Type', 'application/json' )
            res.status( 200 ).json( fallbackMetadata )
        }
    }


    async #handleClientRegistration( { req, res } ) {
        try {
            const { client_name, redirect_uris, grant_types = ['authorization_code'] } = req.body

            const crypto = await import( 'crypto' )
            const client_id = `mcp_${crypto.randomUUID()}`
            const client_secret = crypto.randomBytes( 32 ).toString( 'base64url' )

            const registration = {
                client_id,
                client_secret,
                client_name,
                redirect_uris,
                grant_types,
                token_endpoint_auth_method: 'client_secret_basic',
                created_at: new Date().toISOString()
            }

            res.setHeader( 'Content-Type', 'application/json' )
            res.status( 201 ).json( registration )
        } catch( error ) {
            res.status( 400 ).json( {
                error: 'invalid_client_metadata',
                error_description: error.message
            } )
        }
    }


    #buildOAuthMetadata() {
        // Extract scopes from toolScopes
        const scopes = Array.from(
            new Set( Object.values( this.#toolScopes ).flat() )
        )

        return {
            authorization_servers: [ `${this.#expectedAudience}` ],
            bearer_methods_supported: [ 'header' ],
            resource: this.#expectedAudience,
            resource_documentation: `${this.#expectedAudience}/docs`,
            scopes_supported: scopes.length > 0 ? scopes : [ 'read' ]
        }
    }
}


export { ScaleKitMiddleware }