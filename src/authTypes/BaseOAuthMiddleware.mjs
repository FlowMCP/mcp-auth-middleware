import express from 'express'


class McpSessionCache {
    #sessionToToken = new Map()
    #maxAge = 3600000 // 1 hour

    linkSession( { sessionId, accessToken, method } ) {
        this.#sessionToToken.set( sessionId, {
            accessToken,
            linkedAt: Date.now(),
            method,
            lastUsed: Date.now()
        } )
    }

    getTokenForSession( sessionId ) {
        const entry = this.#sessionToToken.get( sessionId )
        if( !entry ) return null

        // Expiration check
        if( Date.now() - entry.linkedAt > this.#maxAge ) {
            this.#sessionToToken.delete( sessionId )
            return null
        }

        // Update last used
        entry.lastUsed = Date.now()
        return entry.accessToken
    }

    invalidateSession( sessionId ) {
        this.#sessionToToken.delete( sessionId )
    }

    cleanup() {
        const now = Date.now()
        for( const [ sessionId, entry ] of this.#sessionToToken ) {
            if( now - entry.linkedAt > this.#maxAge ) {
                this.#sessionToToken.delete( sessionId )
            }
        }
    }

    getStats() {
        return {
            totalSessions: this.#sessionToToken.size,
            sessions: Array.from( this.#sessionToToken.entries() ).map( ( [ id, data ] ) => ( {
                sessionId: id.substring( 0, 8 ) + '...',
                method: data.method,
                age: Math.floor( ( Date.now() - data.linkedAt ) / 1000 ) + 's'
            } ) )
        }
    }
}


class BaseOAuthMiddleware {
    #sessionCache = new McpSessionCache()
    #attachedRoutes
    #silent

    constructor( { attachedRoutes = [], silent = false } ) {
        this.#attachedRoutes = attachedRoutes
        this.#silent = silent

        // Cleanup old sessions every 10 minutes
        setInterval( () => {
            this.#sessionCache.cleanup()
        }, 600000 )
    }

    router() {
        const router = express.Router()

        // OAuth Well-Known Endpoints - path-specific registration for MCP 2.1 compliance
        const resourcePath = this.#attachedRoutes[0] || ''

        router.get( `${resourcePath}/.well-known/oauth-protected-resource`, ( _req, res ) => {
            return this.handleWellKnownEndpoint( { res } )
        } )

        router.get( `${resourcePath}/.well-known/oauth-authorization-server`, async ( _req, res ) => {
            return this.handleAuthorizationServerMetadata( { res } )
        } )

        // Dynamic Client Registration Endpoint (root level)
        router.post( '/register', ( req, res ) => {
            return this.handleClientRegistration( { req, res } )
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

    #parseJsonRpcMethod( { req } ) {
        try {
            const body = req.body
            if( body && typeof body === 'object' && body.method ) {
                return {
                    method: body.method,
                    id: body.id,
                    isInitialize: body.method === 'initialize',
                    isValidJsonRpc: true
                }
            }
        } catch( error ) {
            // Not valid JSON-RPC
        }
        return {
            method: null,
            isInitialize: false,
            isValidJsonRpc: false
        }
    }

    async #authenticateRequest( { req, res, next } ) {
        try {
            const { method, isInitialize, isValidJsonRpc } = this.#parseJsonRpcMethod( { req } )

            if( !isValidJsonRpc ) {
                // Non-MCP request - normal OAuth handling
                return this.#handleNonMcpRequest( { req, res, next } )
            }

            if( isInitialize ) {
                // Initialize method - intercept response
                return this.#handleInitializeRequest( { req, res, next } )
            } else {
                // Regular MCP method - use session cache
                return this.#handleRegularRequest( { req, res, next } )
            }

        } catch( error ) {
            const errorMessage = error instanceof Error ? error.message : String( error )
            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] AUTH FAILED  - ${errorMessage}` )
            }

            const wwwHeader = this.buildWWWAuthenticateHeader()

            return res
                .status( 401 )
                .set( 'WWW-Authenticate', wwwHeader )
                .end()
        }
    }

    async #handleNonMcpRequest( { req, res, next } ) {
        // Regular OAuth validation for non-MCP requests
        const { token } = this.extractToken( { req } )

        if( !token ) {
            throw new Error( 'Missing or invalid Bearer token' )
        }

        const validationOptions = this.buildValidationOptions( { req } )
        await this.validateToken( token, validationOptions )

        if( !this.#silent ) {
            const timestamp = new Date().toISOString()
            console.log( `[${timestamp}] AUTH SUCCESS - Non-MCP request validated` )
        }

        return next()
    }

    async #handleInitializeRequest( { req, res, next } ) {
        // Token validation for initialize request
        const { token } = this.extractToken( { req } )

        if( !token ) {
            throw new Error( 'Missing or invalid Bearer token' )
        }

        const validationOptions = this.buildValidationOptions( { req } )
        await this.validateToken( token, validationOptions )

        // Intercept response to capture session-id
        const originalSetHeader = res.setHeader.bind( res )
        const validatedToken = token

        res.setHeader = ( name, value ) => {
            if( name.toLowerCase() === 'mcp-session-id' ) {
                // Link session-id with validated token
                this.#sessionCache.linkSession( {
                    sessionId: value,
                    accessToken: validatedToken,
                    method: 'initialize'
                } )

                if( !this.#silent ) {
                    const timestamp = new Date().toISOString()
                    console.log( `[${timestamp}] MCP SESSION  - New session: ${value.substring( 0, 8 )}...` )
                }
            }
            return originalSetHeader( name, value )
        }

        if( !this.#silent ) {
            const timestamp = new Date().toISOString()
            console.log( `[${timestamp}] MCP INIT     - Initialize request validated` )
        }

        return next()
    }

    async #handleRegularRequest( { req, res, next } ) {
        const sessionId = req.headers[ 'mcp-session-id' ]

        if( sessionId ) {
            // Check session cache
            const cachedToken = this.#sessionCache.getTokenForSession( sessionId )
            if( cachedToken ) {
                if( !this.#silent ) {
                    const timestamp = new Date().toISOString()
                    console.log( `[${timestamp}] MCP CACHE    - Using cached token for session: ${sessionId.substring( 0, 8 )}...` )
                }
                return next() // Skip token validation!
            }

            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] MCP MISS     - Session not found in cache: ${sessionId.substring( 0, 8 )}...` )
            }
        }

        // Fallback: Normal token validation
        const { token } = this.extractToken( { req } )

        if( !token ) {
            throw new Error( 'Missing or invalid Bearer token' )
        }

        const validationOptions = this.buildValidationOptions( { req } )
        await this.validateToken( token, validationOptions )

        if( !this.#silent ) {
            const timestamp = new Date().toISOString()
            console.log( `[${timestamp}] MCP VALIDATE - Token validated (no session)` )
        }

        return next()
    }

    // Abstract methods - must be implemented by child classes
    extractToken( { req } ) {
        throw new Error( 'extractToken method must be implemented by child class' )
    }

    buildValidationOptions( { req } ) {
        throw new Error( 'buildValidationOptions method must be implemented by child class' )
    }

    async validateToken( token, validationOptions ) {
        throw new Error( 'validateToken method must be implemented by child class' )
    }

    buildWWWAuthenticateHeader() {
        throw new Error( 'buildWWWAuthenticateHeader method must be implemented by child class' )
    }

    handleWellKnownEndpoint( { res } ) {
        throw new Error( 'handleWellKnownEndpoint method must be implemented by child class' )
    }

    async handleAuthorizationServerMetadata( { res } ) {
        throw new Error( 'handleAuthorizationServerMetadata method must be implemented by child class' )
    }

    async handleClientRegistration( { req, res } ) {
        throw new Error( 'handleClientRegistration method must be implemented by child class' )
    }

    // Utility methods available to child classes
    getSessionStats() {
        return this.#sessionCache.getStats()
    }

    invalidateSession( sessionId ) {
        this.#sessionCache.invalidateSession( sessionId )
    }
}


export { BaseOAuthMiddleware, McpSessionCache }