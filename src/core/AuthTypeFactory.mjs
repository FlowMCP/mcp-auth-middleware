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
        if( authType === 'oauth21_auth0' ) {
            return await AuthTypeFactory.#createOAuth21Auth0Handler( { config, handlerConfig, silent } )
        }

        throw new Error( `No factory implementation found for authType: ${authType}` )
    }


    static async #createOAuth21Auth0Handler( { config, handlerConfig, silent } ) {
        try {
            const { OAuth21Auth0Provider } = await import( handlerConfig.providerPath )
            const { OAuth21Auth0TokenValidator } = await import( handlerConfig.tokenValidatorPath )
            const { OAuth21Auth0FlowHandler } = await import( handlerConfig.flowHandlerPath )

            const provider = new OAuth21Auth0Provider( { config, silent } )
            const tokenValidator = new OAuth21Auth0TokenValidator( { config, silent } )
            const flowHandler = new OAuth21Auth0FlowHandler( { config, silent } )

            const authHandler = {
                authType: 'oauth21_auth0',
                provider,
                tokenValidator,
                flowHandler,
                config
            }

            return authHandler
        } catch( error ) {
            throw new Error( `Failed to create OAuth21Auth0 handler: ${error.message}` )
        }
    }
}

export { AuthTypeFactory }