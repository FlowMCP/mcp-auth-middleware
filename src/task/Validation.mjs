import { AuthTypeValidator } from '../core/AuthTypeValidator.mjs'
import { AuthTypeRegistry } from '../core/AuthTypeRegistry.mjs'


class Validation {
    static validationCreate( createParams ) {
        // Extract known parameters and check for unknown ones
        const { staticBearer, oauth21, silent, baseUrl, forceHttps, ...unknownParams } = createParams || {}
        const struct = { status: false, messages: [] }

        // Check for unknown parameters
        const unknownKeys = Object.keys( unknownParams )
        if( unknownKeys.length > 0 ) {
            struct['messages'].push( `Unknown parameters: ${unknownKeys.join( ', ' )}. Allowed: staticBearer, oauth21, silent, baseUrl, forceHttps` )
        }

        // Check if createParams is provided at all
        if( createParams === undefined || createParams === null ) {
            struct['messages'].push( 'Create parameters object is required' )
            return struct
        }

        // Optional parameter: silent
        if( silent !== undefined && typeof silent !== 'boolean' ) {
            struct['messages'].push( 'silent: Must be a boolean' )
        }

        // Required parameter: baseUrl
        if( baseUrl === undefined || baseUrl === null ) {
            struct['messages'].push( 'baseUrl: Required parameter is missing' )
        } else {
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

        // Validate staticBearer configuration
        if( staticBearer !== undefined && staticBearer !== null ) {
            if( typeof staticBearer !== 'object' ) {
                struct['messages'].push( 'staticBearer: Must be an object' )
            } else {
                // Validate required tokenSecret
                if( staticBearer.tokenSecret === undefined || staticBearer.tokenSecret === null ) {
                    struct['messages'].push( 'staticBearer.tokenSecret: Missing value' )
                } else if( typeof staticBearer.tokenSecret !== 'string' ) {
                    struct['messages'].push( 'staticBearer.tokenSecret: Must be a string' )
                } else if( staticBearer.tokenSecret.trim() === '' ) {
                    struct['messages'].push( 'staticBearer.tokenSecret: Cannot be empty' )
                }

                // Validate required attachedRoutes
                if( staticBearer.attachedRoutes === undefined || staticBearer.attachedRoutes === null ) {
                    struct['messages'].push( 'staticBearer.attachedRoutes: Missing value' )
                } else if( !Array.isArray( staticBearer.attachedRoutes ) ) {
                    struct['messages'].push( 'staticBearer.attachedRoutes: Must be an array' )
                } else if( staticBearer.attachedRoutes.length === 0 ) {
                    struct['messages'].push( 'staticBearer.attachedRoutes: Cannot be empty array' )
                } else {
                    staticBearer.attachedRoutes.forEach( ( route, index ) => {
                        if( typeof route !== 'string' ) {
                            struct['messages'].push( `staticBearer.attachedRoutes[${index}]: Must be a string` )
                        } else if( !route.startsWith( '/' ) ) {
                            struct['messages'].push( `staticBearer.attachedRoutes[${index}]: Must start with /` )
                        }
                    } )
                }
            }
        }

        // Validate oauth21 configuration
        if( oauth21 !== undefined && oauth21 !== null ) {
            if( typeof oauth21 !== 'object' ) {
                struct['messages'].push( 'oauth21: Must be an object' )
            } else {
                // Validate required authType
                if( oauth21.authType === undefined || oauth21.authType === null ) {
                    struct['messages'].push( 'oauth21.authType: Missing value' )
                } else if( typeof oauth21.authType !== 'string' ) {
                    struct['messages'].push( 'oauth21.authType: Must be a string' )
                } else {
                    // For now, only oauth21_scalekit is supported (auth0 deprecated)
                    if( oauth21.authType !== 'oauth21_scalekit' ) {
                        struct['messages'].push( `oauth21.authType: Unsupported value "${oauth21.authType}". Only "oauth21_scalekit" is supported` )
                    }
                }

                // Validate required attachedRoutes
                if( oauth21.attachedRoutes === undefined || oauth21.attachedRoutes === null ) {
                    struct['messages'].push( 'oauth21.attachedRoutes: Missing value' )
                } else if( !Array.isArray( oauth21.attachedRoutes ) ) {
                    struct['messages'].push( 'oauth21.attachedRoutes: Must be an array' )
                } else if( oauth21.attachedRoutes.length === 0 ) {
                    struct['messages'].push( 'oauth21.attachedRoutes: Cannot be empty array' )
                } else {
                    oauth21.attachedRoutes.forEach( ( route, index ) => {
                        if( typeof route !== 'string' ) {
                            struct['messages'].push( `oauth21.attachedRoutes[${index}]: Must be a string` )
                        } else if( !route.startsWith( '/' ) ) {
                            struct['messages'].push( `oauth21.attachedRoutes[${index}]: Must start with /` )
                        }
                    } )
                }

                // Validate required options for oauth21
                if( oauth21.options === undefined || oauth21.options === null ) {
                    struct['messages'].push( 'oauth21.options: Missing value' )
                } else if( typeof oauth21.options !== 'object' ) {
                    struct['messages'].push( 'oauth21.options: Must be an object' )
                } else {
                    // Validate authType-specific configuration using AuthTypeValidator
                    if( oauth21.authType && typeof oauth21.authType === 'string' ) {
                        const authTypeValidation = AuthTypeValidator.validateAuthType( {
                            authType: oauth21.authType,
                            config: oauth21.options
                        } )

                        if( !authTypeValidation.status ) {
                            authTypeValidation.messages.forEach( ( message ) => {
                                struct['messages'].push( `oauth21.options: ${message}` )
                            } )
                        }
                    }
                }
            }
        }

        // Check for route conflicts (same route in both arrays)
        if( staticBearer?.attachedRoutes && oauth21?.attachedRoutes ) {
            const routeConflicts = staticBearer.attachedRoutes
                .filter( route => oauth21.attachedRoutes.includes( route ) )

            if( routeConflicts.length > 0 ) {
                struct['messages'].push( `Route conflict: Routes cannot be in both staticBearer and oauth21 attachedRoutes: ${routeConflicts.join( ', ' )}` )
            }
        }

        // Validate that at least one auth method is configured OR both are null (unprotected server)
        const hasStaticBearer = staticBearer !== null && staticBearer !== undefined
        const hasOAuth21 = oauth21 !== null && oauth21 !== undefined

        if( !hasStaticBearer && !hasOAuth21 ) {
            // Both null/undefined - server will be unprotected (this is allowed)
            // No validation error, just log a note in implementation
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