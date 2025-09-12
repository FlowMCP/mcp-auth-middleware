import { AuthTypeValidator } from '../core/AuthTypeValidator.mjs'
import { AuthTypeRegistry } from '../core/AuthTypeRegistry.mjs'


class Validation {
    static validationCreate( createParams ) {
        // Extract known parameters and check for unknown ones
        const { routes, silent, baseUrl, forceHttps, ...unknownParams } = createParams || {}
        const struct = { status: false, messages: [] }

        // Check for unknown parameters
        const unknownKeys = Object.keys( unknownParams )
        if( unknownKeys.length > 0 ) {
            struct['messages'].push( `Unknown parameters: ${unknownKeys.join( ', ' )}. Allowed: routes, silent, baseUrl, forceHttps` )
        }

        // Check if createParams is provided at all
        if( createParams === undefined || createParams === null ) {
            struct['messages'].push( 'Create parameters object is required' )
            return struct
        }

        // Required parameter: routes
        if( routes === undefined || routes === null ) {
            struct['messages'].push( 'routes: Missing value' )
        } else if( typeof routes !== 'object' || Array.isArray( routes ) ) {
            struct['messages'].push( 'routes: Must be an object' )
        }

        // Optional parameter: silent
        if( silent !== undefined && typeof silent !== 'boolean' ) {
            struct['messages'].push( 'silent: Must be a boolean' )
        }

        // Optional parameter: baseUrl
        if( baseUrl !== undefined ) {
            if( typeof baseUrl !== 'string' ) {
                struct['messages'].push( 'baseUrl: Must be a string' )
            } else if( baseUrl.trim() === '' ) {
                struct['messages'].push( 'baseUrl: Cannot be empty' )
            } else {
                // Validate URL format
                try {
                    const url = new URL( baseUrl )
                    if( ![ 'http:', 'https:' ].includes( url.protocol ) ) {
                        struct['messages'].push( 'baseUrl: Must use http:// or https:// protocol' )
                    }
                    if( url.pathname !== '/' ) {
                        struct['messages'].push( 'baseUrl: Must not contain a path (use protocol://host:port format)' )
                    }
                    if( url.search ) {
                        struct['messages'].push( 'baseUrl: Must not contain query parameters' )
                    }
                    if( url.hash ) {
                        struct['messages'].push( 'baseUrl: Must not contain hash/fragment' )
                    }
                } catch( error ) {
                    struct['messages'].push( `baseUrl: Invalid URL format - ${error.message}` )
                }
            }
        }

        // Optional parameter: forceHttps
        if( forceHttps !== undefined && typeof forceHttps !== 'boolean' ) {
            struct['messages'].push( 'forceHttps: Must be a boolean' )
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