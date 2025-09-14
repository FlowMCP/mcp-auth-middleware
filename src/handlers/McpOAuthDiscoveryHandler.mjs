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

                // Use provider's own metadata generation if available
                if( authHandler.provider && typeof authHandler.provider.generateAuthorizationServerMetadata === 'function' ) {
                    const providerResult = authHandler.provider.generateAuthorizationServerMetadata( { config: routeConfig } )

                    if( providerResult.success ) {
                        if( !this.#silent ) {
                            Logger.info( {
                                silent: this.#silent,
                                message: `Generated provider-specific authorization server metadata for ${routePath} (${routeConfig.authType})`
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

        // Fallback to default metadata generation
        const { providerUrl, scope } = routeConfig

        if( !providerUrl ) {
            return {
                success: false,
                error: `Provider URL not configured for route ${routePath}`
            }
        }

        if( !scope ) {
            return {
                success: false,
                error: `Scope not configured for route ${routePath}`
            }
        }

        const scopes = scope.split( ' ' )

        const metadata = {
            issuer: providerUrl,
            authorization_endpoint: `${providerUrl}/authorize`,
            token_endpoint: `${providerUrl}/oauth/token`,
            userinfo_endpoint: `${providerUrl}/userinfo`,
            jwks_uri: `${providerUrl}/.well-known/jwks.json`,
            // Dynamic client registration removed - not universally supported
            scopes_supported: scopes,
            response_types_supported: [ 'code' ],
            response_modes_supported: [ 'query', 'form_post' ],
            grant_types_supported: [ 'authorization_code' ],
            code_challenge_methods_supported: [ 'S256' ],
            token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ],
            subject_types_supported: [ 'public' ],
            claims_supported: [ 'sub', 'iat', 'exp', 'aud', 'iss', 'scope' ]
        }

        if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Generated default OAuth authorization server metadata for ${routePath}`
            } )
        }

        return {
            success: true,
            metadata
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