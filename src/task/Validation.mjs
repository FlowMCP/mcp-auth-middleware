class Validation {
    static validationCreate( { realmsByRoute, silent } ) {
        const struct = { status: false, messages: [] }

        if( realmsByRoute === undefined || realmsByRoute === null ) {
            struct['messages'].push( 'realmsByRoute: Missing value' )
        } else if( typeof realmsByRoute !== 'object' || Array.isArray( realmsByRoute ) ) {
            struct['messages'].push( 'realmsByRoute: Must be an object' )
        }

        if( silent !== undefined && typeof silent !== 'boolean' ) {
            struct['messages'].push( 'silent: Must be a boolean' )
        }

        if( struct['messages'].length > 0 ) {
            return struct
        }

        // Validate realmsByRoute structure
        if( typeof realmsByRoute === 'object' && !Array.isArray( realmsByRoute ) ) {
            Object.entries( realmsByRoute ).forEach( ( [ routePath, config ] ) => {
                if( !routePath || !routePath.startsWith( '/' ) ) {
                    struct['messages'].push( `Route "${routePath}": Must start with /` )
                }

                if( !config || typeof config !== 'object' ) {
                    struct['messages'].push( `Route "${routePath}": Configuration must be an object` )
                } else {
                    const requiredFields = [ 'keycloakUrl', 'realm', 'clientId', 'clientSecret', 'requiredScopes', 'resourceUri' ]
                    const missing = requiredFields.filter( field => !config[field] )
                    
                    if( missing.length > 0 ) {
                        struct['messages'].push( `Route "${routePath}": Missing required fields: ${missing.join( ', ' )}` )
                    }

                    if( config.keycloakUrl && typeof config.keycloakUrl !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": keycloakUrl must be a string` )
                    }

                    if( config.realm && typeof config.realm !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": realm must be a string` )
                    }

                    if( config.clientId && typeof config.clientId !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": clientId must be a string` )
                    }

                    if( config.clientSecret && typeof config.clientSecret !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": clientSecret must be a string` )
                    }

                    if( config.requiredScopes && !Array.isArray( config.requiredScopes ) ) {
                        struct['messages'].push( `Route "${routePath}": requiredScopes must be an array` )
                    }

                    if( config.resourceUri && typeof config.resourceUri !== 'string' ) {
                        struct['messages'].push( `Route "${routePath}": resourceUri must be a string` )
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
}


export { Validation }