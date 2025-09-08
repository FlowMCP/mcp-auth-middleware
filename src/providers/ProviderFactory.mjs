import { Auth0Provider } from './Auth0Provider.mjs'
import { BaseProvider } from './BaseProvider.mjs'


class ProviderFactory {
    static createProvider( { provider, config, silent = false } ) {
        const { status, messages } = BaseProvider.validateProviderConfig( { provider, config } )
        
        if( !status ) {
            throw new Error( `Provider validation failed: ${messages.join( ', ' )}` )
        }

        switch( provider ) {
            case 'auth0':
                const { status: auth0Status, messages: auth0Messages } = Auth0Provider.validateAuth0Config( { config } )
                if( !auth0Status ) {
                    throw new Error( `Auth0 provider validation failed: ${auth0Messages.join( ', ' )}` )
                }
                return new Auth0Provider( { config, silent } )
            
            default:
                throw new Error( `Unsupported provider: ${provider}. Supported providers: ${BaseProvider.getSupportedProviders().join( ', ' )}` )
        }
    }


    static getSupportedProviders() {
        return BaseProvider.getSupportedProviders()
    }


    static validateRealmsByRoute( { realmsByRoute } ) {
        const struct = { status: false, messages: [] }
        
        if( !realmsByRoute || typeof realmsByRoute !== 'object' || Array.isArray( realmsByRoute ) ) {
            struct['messages'].push( 'realmsByRoute must be a non-array object' )
            return struct
        }

        Object.entries( realmsByRoute ).forEach( ( [ routePath, config ] ) => {
            if( !config.providerName ) {
                struct['messages'].push( `Route "${routePath}": Missing providerName field` )
                return
            }

            try {
                ProviderFactory.createProvider( { 
                    provider: config.providerName, 
                    config, 
                    silent: true 
                } )
            } catch( error ) {
                struct['messages'].push( `Route "${routePath}": ${error.message}` )
            }
        } )

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    static createProvidersForRoutes( { realmsByRoute, silent = false } ) {
        const { status, messages } = ProviderFactory.validateRealmsByRoute( { realmsByRoute } )
        
        if( !status ) {
            throw new Error( `Route validation failed: ${messages.join( ', ' )}` )
        }

        const providers = {}
        
        Object.entries( realmsByRoute ).forEach( ( [ routePath, config ] ) => {
            const provider = ProviderFactory.createProvider( { 
                provider: config.providerName, 
                config, 
                silent 
            } )
            providers[ routePath ] = provider
        } )

        return { providers }
    }
}


export { ProviderFactory }