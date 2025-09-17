import { AuthTypeRegistry } from './AuthTypeRegistry.mjs'


class AuthTypeValidator {
    static validateAuthType( { authType, config } ) {
        const { authType: authTypeValue, config: configValue } = { authType, config }
        const struct = { status: false, messages: [] }

        if( authTypeValue === undefined ) {
            struct['messages'].push( 'authType: Missing value' )
        } else if( typeof authTypeValue !== 'string' ) {
            struct['messages'].push( 'authType: Must be a string' )
        }

        if( configValue === undefined ) {
            struct['messages'].push( 'config: Missing value' )
        } else if( typeof configValue !== 'object' || configValue === null ) {
            struct['messages'].push( 'config: Must be an object' )
        }

        if( struct['messages'].length > 0 ) {
            return struct
        }

        const { isSupported } = AuthTypeRegistry.isSupported( { authType: authTypeValue } )
        if( !isSupported ) {
            const { authTypes } = AuthTypeRegistry.getSupportedAuthTypes()
            struct['messages'].push( `authType: Unknown type "${authTypeValue}". Supported types: ${authTypes.join( ', ' )}` )
            return struct
        }

        const schemaValidation = AuthTypeValidator.#validateSchemaForAuthType( { authType: authTypeValue, config: configValue } )
        if( !schemaValidation.status ) {
            struct['messages'].push( ...schemaValidation.messages )
            return struct
        }

        struct['status'] = true
        return struct
    }


    static #validateSchemaForAuthType( { authType, config } ) {
        const struct = { status: false, messages: [] }

        if( authType === 'oauth21_scalekit' ) {
            return AuthTypeValidator.#validateOAuth21ScalekitSchema( { config } )
        }

        if( authType === 'staticBearer' ) {
            return AuthTypeValidator.#validateStaticBearerSchema( { config } )
        }

        struct['messages'].push( `No schema validator found for authType: ${authType}` )
        return struct
    }


    static #validateOAuth21ScalekitSchema( { config } ) {
        const struct = { status: false, messages: [] }

        const requiredFields = [
            [ 'providerUrl', 'string' ],
            [ 'mcpId', 'string' ],
            [ 'clientId', 'string' ],
            [ 'clientSecret', 'string' ],
            [ 'resource', 'string' ],
            [ 'scope', 'string' ]
        ]

        const missingFields = []
        const typeErrors = []

        requiredFields
            .forEach( ( [ key, type ] ) => {
                const value = config[ key ]
                if( value === undefined || value === null ) {
                    missingFields.push( key )
                } else if( typeof value !== type ) {
                    typeErrors.push( `${key}: Must be a ${type}` )
                }
            } )

        if( missingFields.length > 0 ) {
            struct['messages'].push( `OAuth21 ScaleKit configuration missing required fields: ${missingFields.join( ', ' )}` )
        }

        if( typeErrors.length > 0 ) {
            struct['messages'].push( ...typeErrors.map( error => `OAuth21 ScaleKit configuration ${error}` ) )
        }

        // ScaleKit custom domain support - no domain restriction
        if( config.providerUrl && typeof config.providerUrl === 'string' ) {
            try {
                new URL( config.providerUrl )
            } catch( error ) {
                struct['messages'].push( `OAuth21 ScaleKit configuration requires valid URL in providerUrl, got: ${config.providerUrl}` )
            }
        }

        // ScaleKit-specific mcpId validation
        if( config.mcpId && typeof config.mcpId === 'string' ) {
            if( !config.mcpId.startsWith( 'res_' ) ) {
                struct['messages'].push( `OAuth21 ScaleKit configuration requires mcpId to start with 'res_', got: ${config.mcpId}` )
            }
        }

        const optionalFields = [
            [ 'resourceDocumentation', 'string' ],
            [ 'routePath', 'string' ],
            [ 'redirectUri', 'string' ],
            [ 'responseType', 'string' ],
            [ 'grantType', 'string' ],
            [ 'tokenEndpoint', 'string' ],
            [ 'userInfoEndpoint', 'string' ]
        ]

        optionalFields
            .forEach( ( [ key, type ] ) => {
                const value = config[ key ]
                if( value !== undefined && typeof value !== type ) {
                    struct['messages'].push( `config.${key}: Must be a ${type} when provided` )
                }
            } )

        if( struct['messages'].length > 0 ) {
            return struct
        }

        struct['status'] = true
        return struct
    }


    static #validateStaticBearerSchema( { config } ) {
        const struct = { status: false, messages: [] }

        const requiredFields = [
            [ 'tokenSecret', 'string' ]
        ]

        const missingFields = []
        const typeErrors = []

        requiredFields
            .forEach( ( [ key, type ] ) => {
                const value = config[ key ]
                if( value === undefined || value === null ) {
                    missingFields.push( key )
                } else if( typeof value !== type ) {
                    typeErrors.push( `config.${key}: Must be a ${type}` )
                }
            } )

        if( missingFields.length > 0 ) {
            struct['messages'].push( `StaticBearer configuration missing required fields: ${missingFields.join( ', ' )}` )
        }

        struct['messages'].push( ...typeErrors )

        if( config.tokenSecret && typeof config.tokenSecret === 'string' ) {
            if( config.tokenSecret.trim().toLowerCase().startsWith( 'bearer' ) ) {
                struct['messages'].push( `StaticBearer token must not start with "Bearer" prefix` )
            }
            if( config.tokenSecret.trim().length < 8 ) {
                struct['messages'].push( `StaticBearer token must be at least 8 characters long` )
            }
        }

        if( struct['messages'].length > 0 ) {
            return struct
        }

        struct['status'] = true
        return struct
    }
}

export { AuthTypeValidator }