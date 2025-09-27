import express from 'express'


class StaticBearerMiddleware {
    #bearerToken
    #attachedRoutes
    #silent


    constructor( { options, attachedRoutes = [], silent = false } ) {
        const { bearerToken } = options

        this.#bearerToken = bearerToken
        this.#attachedRoutes = attachedRoutes
        this.#silent = silent
    }


    static async create( { options, attachedRoutes = [], silent = false } ) {
        // Validate required options
        const messages = []
        if( !options.bearerToken ) {
            messages.push( 'StaticBearer: Missing required option: bearerToken' )
        }
        if( messages.length > 0 ) {
            throw new Error( messages.join( '; ' ) )
        }

        const middleware = new StaticBearerMiddleware( { options, attachedRoutes, silent } )

        if( !silent ) {
            console.log( '\n' + '-'.repeat( 80 ) )
            console.log( ' AUTHENTICATION MIDDLEWARE' )
            console.log( '-'.repeat( 80 ) )
            console.log( ` Type:                 Static Bearer Token` )
            console.log( ` Token Length:         ${options.bearerToken.length} characters` )
            console.log( ` Token Preview:        ${options.bearerToken.substring( 0, 4 )}${'*'.repeat( Math.min( options.bearerToken.length - 4, 20 ) )}` )
            console.log( ` Protected Routes:     ${attachedRoutes.join( ', ' ) || 'none'}` )
            console.log( ` WWW-Authenticate:     Bearer realm="Static Token"` )
            console.log( '' )
            console.log( ` Required Request Header:` )
            console.log( ` {` )
            console.log( `   "Authorization": "Bearer ${options.bearerToken}"` )
            console.log( ` }` )
            console.log( '-'.repeat( 80 ) + '\n' )
        }

        return middleware
    }


    router() {
        const router = express.Router()

        // Authentication middleware for all routes
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


    #authenticateRequest( { req, res, next } ) {
        try {
            const { token } = this.#extractToken( { req } )

            if( !token ) {
                throw new Error( 'Missing or invalid Bearer token' )
            }

            // Simple string comparison for static bearer token
            if( token !== this.#bearerToken ) {
                throw new Error( 'Invalid Bearer token' )
            }

            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] AUTH SUCCESS - Token validated for audience: static-bearer` )
            }

            return next()
        } catch( error ) {
            const errorMessage = error instanceof Error ? error.message : String( error )
            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] AUTH FAILED  - ${errorMessage}` )
            }

            const wwwHeader = 'Bearer realm="Static Token", error="invalid_token", error_description="The access token is missing or invalid"'

            return res
                .status( 401 )
                .set( 'WWW-Authenticate', wwwHeader )
                .json( { error: 'invalid_token', error_description: 'Missing or invalid access token' } )
        }
    }


    #extractToken( { req } ) {
        const authHeader = req.headers[ 'authorization' ]
        const token = authHeader?.startsWith( 'Bearer ' ) ?
            authHeader.split( 'Bearer ' )[ 1 ]?.trim() :
            null

        return { token }
    }
}


export { StaticBearerMiddleware }