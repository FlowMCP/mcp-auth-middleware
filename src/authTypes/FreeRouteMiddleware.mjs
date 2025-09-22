import express from 'express'


class FreeRouteMiddleware {
    #silent


    constructor( { options = {}, attachedRoutes = [], silent = false } ) {
        this.#silent = silent
    }


    static async create( { options = {}, attachedRoutes = [], silent = false } ) {
        const middleware = new FreeRouteMiddleware( { options, attachedRoutes, silent } )

        if( !silent ) {
            console.log( '\n' + '-'.repeat( 80 ) )
            console.log( ' AUTHENTICATION MIDDLEWARE' )
            console.log( '-'.repeat( 80 ) )
            console.log( ` Type:                 Free Route (No Authentication)` )
            console.log( ` Protected Routes:     none` )
            console.log( ` Authorization:        Not required` )
            console.log( ` Request Header:       None` )
            console.log( '-'.repeat( 80 ) + '\n' )
        }

        return middleware
    }


    router() {
        const router = express.Router()

        // No authentication - all routes pass through
        router.use( ( req, res, next ) => {
            if( !this.#silent ) {
                const timestamp = new Date().toISOString()
                console.log( `[${timestamp}] FREE ACCESS - No authentication required for ${req.method} ${req.path}` )
            }

            return next()
        } )

        return router
    }
}


export { FreeRouteMiddleware }