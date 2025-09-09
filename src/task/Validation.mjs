import { AuthTypeValidator } from '../core/AuthTypeValidator.mjs'
import { AuthTypeRegistry } from '../core/AuthTypeRegistry.mjs'


class Validation {
    static validationCreate( { routes, silent } ) {
        const struct = { status: false, messages: [] }

        if( routes === undefined || routes === null ) {
            struct['messages'].push( 'routes: Missing value' )
        } else if( typeof routes !== 'object' || Array.isArray( routes ) ) {
            struct['messages'].push( 'routes: Must be an object' )
        }

        if( silent !== undefined && typeof silent !== 'boolean' ) {
            struct['messages'].push( 'silent: Must be a boolean' )
        }

        if( struct['messages'].length > 0 ) {
            return struct
        }

        // Validate routes structure
        if( typeof routes === 'object' && !Array.isArray( routes ) ) {
            Object.entries( routes ).forEach( ( [ routePath, config ] ) => {
                if( !routePath || !routePath.startsWith( '/' ) ) {
                    struct['messages'].push( `Route "${routePath}": Must start with /` )
                }

                if( !config || typeof config !== 'object' ) {
                    struct['messages'].push( `Route "${routePath}": Configuration must be an object` )
                } else {
                    // Validate required authType field
                    if( !config.authType ) {
                        struct['messages'].push( `Route "${routePath}": Missing required field: authType` )
                    } else if( typeof config.authType !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": authType must be a string` )
                    } else {
                        // Validate authType configuration using AuthTypeValidator
                        const authTypeValidation = AuthTypeValidator.validateAuthType( { 
                            authType: config.authType, 
                            config 
                        } )
                        
                        if( !authTypeValidation.status ) {
                            authTypeValidation.messages.forEach( ( message ) => {
                                struct['messages'].push( `Route "${routePath}": ${message}` )
                            } )
                        }
                    }

                }
            } )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    static validationGetRouteConfig( { routePath } ) {
        const struct = { status: false, messages: [] }

        if( routePath === undefined || routePath === null ) {
            struct['messages'].push( 'routePath: Missing value' )
        } else if( typeof routePath !== 'string' ) {
            struct['messages'].push( 'routePath: Must be a string' )
        } else if( !routePath.startsWith( '/' ) ) {
            struct['messages'].push( 'routePath: Must start with /' )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    static getSupportedAuthTypes() {
        const { authTypes } = AuthTypeRegistry.getSupportedAuthTypes()
        
        return { authTypes }
    }


    static validateAuthTypeConfig( { authType, config } ) {
        return AuthTypeValidator.validateAuthType( { authType, config } )
    }
}


export { Validation }