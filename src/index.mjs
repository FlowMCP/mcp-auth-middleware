import { McpAuthMiddleware as McpAuthMiddlewareImpl } from './task/McpAuthMiddleware.mjs'
import { OAuthMiddlewareTester } from './tester/OAuthMiddlewareTester.mjs'
import { Validation } from './task/Validation.mjs'


class McpAuthMiddleware {
    #impl


    constructor( impl ) {
        this.#impl = impl
    }


    static async create( { staticBearer = null, oauth21 = null, silent = false, baseUrl, forceHttps = false } ) {
        const { status, messages } = Validation.validationCreate( { staticBearer, oauth21, silent, baseUrl, forceHttps } )
        if( !status ) {
            throw new Error( `Validation failed: ${messages.join( ', ' )}` )
        }

        const impl = await McpAuthMiddlewareImpl.create( { staticBearer, oauth21, silent, baseUrl, forceHttps } )
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


}


export { McpAuthMiddleware, OAuthMiddlewareTester }