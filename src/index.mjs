import { McpAuthMiddleware as McpAuthMiddlewareImpl } from './task/McpAuthMiddleware.mjs'
import { Validation } from './task/Validation.mjs'


class McpAuthMiddleware {
    #impl


    constructor( impl ) {
        this.#impl = impl
    }


    static async create( { routes, silent = false, baseUrl = 'http://localhost:3000', forceHttps = false } ) {
        const { status, messages } = Validation.validationCreate( { routes, silent, baseUrl, forceHttps } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        const impl = await McpAuthMiddlewareImpl.create( { routes, silent, baseUrl, forceHttps } )
        return new McpAuthMiddleware( impl )
    }


    router() {
        return this.#impl.router()
    }


    getRouteConfig( { routePath } ) {
        const { status, messages } = Validation.validationGetRouteConfig( { routePath } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        return this.#impl.getRouteConfig( { routePath } )
    }


    getRouteClient( { routePath } ) {
        const { status, messages } = Validation.validationGetRouteConfig( { routePath } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        return this.#impl.getRouteClient( { routePath } )
    }


    getRoutes() {
        return this.#impl.getRoutes()
    }


    getRealms() {
        return this.#impl.getRealms()
    }
}


export { McpAuthMiddleware }