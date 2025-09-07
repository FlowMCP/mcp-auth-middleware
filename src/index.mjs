import { OAuthMiddleware as OAuthMiddlewareImpl } from './task/OAuthMiddleware.mjs'
import { Validation } from './task/Validation.mjs'


class OAuthMiddleware {
    #impl


    constructor( impl ) {
        this.#impl = impl
    }


    static async create( { realmsByRoute, silent = false } ) {
        const { status, messages } = Validation.validationCreate( { realmsByRoute, silent } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        const impl = await OAuthMiddlewareImpl.create( { realmsByRoute, silent } )
        return new OAuthMiddleware( impl )
    }


    router() {
        return this.#impl.router()
    }


    getRouteConfig( routePath ) {
        const { status, messages } = Validation.validationGetRouteConfig( { routePath } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        return this.#impl.getRouteConfig( routePath )
    }


    getRouteClient( routePath ) {
        const { status, messages } = Validation.validationGetRouteConfig( { routePath } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        return this.#impl.getRouteClient( routePath )
    }


    getRoutes() {
        return this.#impl.getRoutes()
    }


    getRealms() {
        return this.#impl.getRealms()
    }
}


export { OAuthMiddleware }