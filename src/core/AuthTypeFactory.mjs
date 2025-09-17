import { AuthTypeRegistry } from './AuthTypeRegistry.mjs'
import { AuthTypeValidator } from './AuthTypeValidator.mjs'


class AuthTypeFactory {
    static async createAuthHandler( { authType, config, silent = false } ) {
        const validationResult = AuthTypeValidator.validateAuthType( { authType, config } )
        if( !validationResult.status ) {
            throw new Error( `AuthType validation failed: ${validationResult.messages.join( ', ' )}` )
        }

        const { handler: handlerConfig } = AuthTypeRegistry.getHandler( { authType } )
        const authHandler = await AuthTypeFactory.#instantiateHandler( { 
            authType, 
            config, 
            handlerConfig, 
            silent 
        } )

        return authHandler
    }


    static async #instantiateHandler( { authType, config, handlerConfig, silent } ) {
        if( authType === 'oauth21_scalekit' ) {
            return await AuthTypeFactory.#createOAuth21ScalekitHandler( { config, handlerConfig, silent } )
        }

        if( authType === 'staticBearer' ) {
            return await AuthTypeFactory.#createStaticBearerHandler( { config, handlerConfig, silent } )
        }

        throw new Error( `No factory implementation found for authType: ${authType}` )
    }


    static async #createOAuth21ScalekitHandler( { config, handlerConfig, silent } ) {
        try {
            const { OAuth21ScalekitProvider } = await import( handlerConfig.providerPath )
            const { OAuth21ScalekitTokenValidator } = await import( handlerConfig.tokenValidatorPath )
            const { OAuth21ScalekitFlowHandler } = await import( handlerConfig.flowHandlerPath )

            const provider = new OAuth21ScalekitProvider( { config, silent } )

            // Generate endpoints and integrate them into config
            const { endpoints } = provider.generateEndpoints( { config } )
            const enhancedConfig = {
                ...config,
                ...endpoints  // Add generated endpoints to config
            }

            const tokenValidator = new OAuth21ScalekitTokenValidator( { config: enhancedConfig, silent } )
            const flowHandler = new OAuth21ScalekitFlowHandler( { config: enhancedConfig, silent } )

            const authHandler = {
                authType: 'oauth21_scalekit',
                provider,
                tokenValidator,
                flowHandler,
                config: enhancedConfig  // Use enhanced config with endpoints
            }

            return authHandler
        } catch( error ) {
            throw new Error( `Failed to create OAuth21Scalekit handler: ${error.message}` )
        }
    }


    static async #createStaticBearerHandler( { config, handlerConfig, silent } ) {
        try {
            const { StaticBearerProvider } = await import( handlerConfig.providerPath )
            const { StaticBearerTokenValidator } = await import( handlerConfig.tokenValidatorPath )

            const provider = new StaticBearerProvider( { config, silent } )
            const tokenValidator = new StaticBearerTokenValidator( { config, silent } )

            const authHandler = {
                authType: 'staticBearer',
                provider,
                tokenValidator,
                flowHandler: null,
                config
            }

            return authHandler
        } catch( error ) {
            throw new Error( `Failed to create StaticBearer handler: ${error.message}` )
        }
    }
}

export { AuthTypeFactory }