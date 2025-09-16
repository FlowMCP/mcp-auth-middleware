import { Logger } from '../helpers/Logger.mjs'
import { AuthTypeFactory } from '../core/AuthTypeFactory.mjs'


class McpOAuthDiscoveryHandler {
    #routes
    #silent
    #baseUrl


    constructor( { routes, silent = false, baseUrl } ) {
        this.#routes = routes
        this.#silent = silent
        this.#baseUrl = baseUrl
    }


    static create( { routes, silent = false, baseUrl } ) {
        return new McpOAuthDiscoveryHandler( { routes, silent, baseUrl } )
    }


    async generateAuthorizationServerMetadata( { routePath } ) {
        const routeConfig = this.#routes[ routePath ]

        if( !routeConfig ) {
            return {
                success: false,
                error: `Route ${routePath} not found`
            }
        }

        // Check if route has authType and use provider delegation
        if( routeConfig.authType ) {
            try {
                const authHandler = await AuthTypeFactory.createAuthHandler( {
                    authType: routeConfig.authType,
                    config: routeConfig,
                    silent: this.#silent
                } )

                // Use provider's own discovery metadata generation if available (preferred)
                if( authHandler.provider && typeof authHandler.provider.getDiscoveryMetadata === 'function' ) {
                    const providerResult = authHandler.provider.getDiscoveryMetadata( { config: routeConfig } )

                    if( providerResult.success ) {
                        if( !this.#silent ) {
                            Logger.info( {
                                silent: this.#silent,
                                message: `Generated provider-specific discovery metadata for ${routePath} (${routeConfig.authType})`
                            } )
                        }
                        return providerResult
                    }
                }

                // Fallback to legacy method for backward compatibility
                if( authHandler.provider && typeof authHandler.provider.generateAuthorizationServerMetadata === 'function' ) {
                    const providerResult = authHandler.provider.generateAuthorizationServerMetadata( { config: routeConfig } )

                    if( providerResult.success ) {
                        if( !this.#silent ) {
                            Logger.info( {
                                silent: this.#silent,
                                message: `Generated provider-specific authorization server metadata for ${routePath} (${routeConfig.authType}) via legacy method`
                            } )
                        }
                        return providerResult
                    }
                }
            } catch( error ) {
                Logger.warn( {
                    silent: this.#silent,
                    message: `Provider delegation failed for authorization server metadata ${routePath}, falling back to default: ${error.message}`
                } )
            }
        }

        // No valid provider found - this should not happen with supported authTypes
        Logger.error( {
            silent: this.#silent,
            message: `No provider found that supports discovery metadata generation for route ${routePath} with authType ${routeConfig.authType}`
        } )

        return {
            success: false,
            error: `Unsupported authType ${routeConfig.authType} for route ${routePath}. Provider must implement getDiscoveryMetadata() method.`
        }
    }


    async generateProtectedResourceMetadata( { routePath } ) {
        const routeConfig = this.#routes[ routePath ]

        if( !routeConfig ) {
            return {
                success: false,
                error: `Route ${routePath} not found`
            }
        }

        // Check if route has authType and use provider delegation
        if( routeConfig.authType ) {
            try {
                const authHandler = await AuthTypeFactory.createAuthHandler( {
                    authType: routeConfig.authType,
                    config: routeConfig,
                    silent: this.#silent
                } )

                // Use provider's own metadata generation if available
                if( authHandler.provider && typeof authHandler.provider.generateProtectedResourceMetadata === 'function' ) {
                    const providerResult = authHandler.provider.generateProtectedResourceMetadata( { config: routeConfig } )

                    if( providerResult.success ) {
                        if( !this.#silent ) {
                            Logger.info( {
                                silent: this.#silent,
                                message: `Generated provider-specific metadata for ${routePath} (${routeConfig.authType})`
                            } )
                        }
                        return providerResult
                    }
                }
            } catch( error ) {
                Logger.warn( {
                    silent: this.#silent,
                    message: `Provider delegation failed for ${routePath}, falling back to default: ${error.message}`
                } )
            }
        }

        // Fallback to default metadata generation
        const { providerUrl, audience, scope } = routeConfig
        const scopes = scope ? scope.split( ' ' ) : []

        const metadata = {
            resource: audience,
            authorization_servers: [ providerUrl ],
            scopes_supported: scopes,
            bearer_methods_supported: [ 'header' ],
            resource_documentation: `MCP OAuth protected resource for ${routePath}`
        }

        if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Generated default OAuth protected resource metadata for ${routePath}`
            } )
        }

        return {
            success: true,
            metadata
        }
    }


    createDiscoveryRoutes( { app } ) {
        const routePaths = Object.keys( this.#routes )

        routePaths
            .forEach( ( routePath ) => {
                const authServerPath = `${routePath}/.well-known/oauth-authorization-server`
                const protectedResourcePath = `${routePath}/.well-known/oauth-protected-resource`

                app.get( authServerPath, async ( req, res ) => {
                    try {
                        const { success, metadata, error } = await this.generateAuthorizationServerMetadata( { routePath } )

                        if( !success ) {
                            return res.status( 404 ).json( { error } )
                        }

                        res.set( {
                            'Content-Type': 'application/json',
                            'Cache-Control': 'public, max-age=3600'
                        } )

                        res.json( metadata )
                    } catch( handlerError ) {
                        Logger.error( {
                            silent: this.#silent,
                            message: `Error generating authorization server metadata for ${routePath}: ${handlerError.message}`
                        } )

                        res.status( 500 ).json( {
                            error: 'Internal server error generating authorization server metadata'
                        } )
                    }
                } )

                app.get( protectedResourcePath, async ( req, res ) => {
                    try {
                        const { success, metadata, error } = await this.generateProtectedResourceMetadata( { routePath } )

                        if( !success ) {
                            return res.status( 404 ).json( { error } )
                        }

                        res.set( {
                            'Content-Type': 'application/json',
                            'Cache-Control': 'public, max-age=3600'
                        } )

                        res.json( metadata )
                    } catch( handlerError ) {
                        Logger.error( {
                            silent: this.#silent,
                            message: `Error generating protected resource metadata for ${routePath}: ${handlerError.message}`
                        } )

                        res.status( 500 ).json( {
                            error: 'Internal server error generating metadata'
                        } )
                    }
                } )

                if( !this.#silent ) {
                    Logger.info( { 
                        silent: this.#silent, 
                        message: `Registered discovery endpoints for ${routePath}` 
                    } )
                }
            } )

        return { 
            success: true, 
            registeredRoutes: routePaths.length 
        }
    }


    getRoutes() {
        return { ...this.#routes }
    }
}

export { McpOAuthDiscoveryHandler }