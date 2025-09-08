class BaseProvider {
    #config
    #silent


    constructor( { config, silent = false } ) {
        if( this.constructor === BaseProvider ) {
            throw new Error( 'BaseProvider is abstract and cannot be instantiated directly' )
        }
        this.#config = config
        this.#silent = silent
    }


    getConfig() {
        return this.#config
    }


    isSilent() {
        return this.#silent
    }


    detectProviderType( { keycloakUrl } ) {
        throw new Error( 'detectProviderType must be implemented by subclass' )
    }


    normalizeConfiguration( { config } ) {
        throw new Error( 'normalizeConfiguration must be implemented by subclass' )
    }


    generateEndpoints( { config } ) {
        throw new Error( 'generateEndpoints must be implemented by subclass' )
    }


    static getSupportedProviders() {
        return [ 'auth0' ]
    }


    static validateProviderConfig( { provider, config } ) {
        const struct = { status: false, messages: [] }

        if( !provider ) {
            struct['messages'].push( 'Provider is required' )
            return struct
        }

        const supportedProviders = BaseProvider.getSupportedProviders()
        if( !supportedProviders.includes( provider ) ) {
            struct['messages'].push( `Unsupported provider: ${provider}. Supported: ${supportedProviders.join( ', ' )}` )
            return struct
        }

        if( !config || typeof config !== 'object' ) {
            struct['messages'].push( 'Provider configuration is required' )
            return struct
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }
}


export { BaseProvider }