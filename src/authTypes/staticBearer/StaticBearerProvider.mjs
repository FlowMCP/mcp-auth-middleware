import { Logger } from '../../helpers/Logger.mjs'


class StaticBearerProvider {
    #config
    #silent


    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }


    detectProviderType( { config } ) {
        return !!(config && config.tokenSecret && typeof config.tokenSecret === 'string')
    }


    normalizeConfiguration( { config } ) {
        const normalizedConfig = {
            tokenSecret: config.tokenSecret.trim(),
            authType: 'staticBearer',
            realm: 'static-bearer'
        }

        return { normalizedConfig }
    }


    generateEndpoints() {
        const endpoints = {}

        return { endpoints }
    }


    static validateStaticBearerConfig( { config } ) {
        const struct = { status: false, messages: [] }

        if( !config || typeof config !== 'object' ) {
            struct['messages'].push( 'StaticBearer config must be a valid object' )
            return struct
        }

        if( !config.tokenSecret || typeof config.tokenSecret !== 'string' ) {
            struct['messages'].push( 'StaticBearer config missing required field: tokenSecret (must be string)' )
        }

        if( config.tokenSecret && typeof config.tokenSecret === 'string' && config.tokenSecret.trim().toLowerCase().startsWith( 'bearer' ) ) {
            struct['messages'].push( 'StaticBearer token must not start with "Bearer" prefix' )
        }

        if( config.tokenSecret && typeof config.tokenSecret === 'string' && config.tokenSecret.trim().length < 8 ) {
            struct['messages'].push( 'StaticBearer token must be at least 8 characters long' )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    getProviderName() {
        return 'staticBearer'
    }


    getDisplayName() {
        return 'Static Bearer Token'
    }


    static getSupportedFlows() {
        return []
    }


    static getDefaultScopes() {
        return ''
    }


    static getAuthType() {
        return 'staticBearer'
    }
}

export { StaticBearerProvider }