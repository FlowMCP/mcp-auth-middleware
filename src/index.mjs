import { FreeRouteMiddleware } from './authTypes/FreeRouteMiddleware.mjs'
import { ScaleKitMiddleware } from './authTypes/ScaleKitMiddleware.mjs'
import { StaticBearerMiddleware } from './authTypes/StaticBearerMiddleware.mjs'
import { AuthKitMiddleware } from './authTypes/AuthKitMiddleware.mjs'


class McpAuthMiddleware {
    static async create( mcpAuthConfig ) {
        const { authType, options, attachedRoutes, silent = false } = mcpAuthConfig

        let middlewareInstance = null
        switch( authType ) {
            case 'free-route':
                middlewareInstance = await FreeRouteMiddleware
                    .create( { options, attachedRoutes, silent } )
                break
            case 'static-bearer':
                middlewareInstance = await StaticBearerMiddleware
                    .create( { options, attachedRoutes, silent } )
                break
            case 'scalekit':
                middlewareInstance = await ScaleKitMiddleware
                    .create( { options, attachedRoutes, silent } )
                break
            case 'authkit':
                middlewareInstance = await AuthKitMiddleware
                    .create( { options, attachedRoutes, silent } )
                break
            default:
                throw new Error(`Unsupported authType: ${authType}. Supported types: free-route, static-bearer, scalekit, authkit`)
        }

        return middlewareInstance
    }
}


export { McpAuthMiddleware, FreeRouteMiddleware, ScaleKitMiddleware, StaticBearerMiddleware, AuthKitMiddleware }