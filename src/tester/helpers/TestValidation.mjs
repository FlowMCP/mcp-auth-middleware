class TestValidation {
    static validationTestStreamableRoute( { baseUrl, routePath } ) {
        const struct = { status: false, messages: [] }

        if( baseUrl === undefined || baseUrl === null ) {
            struct.messages.push( 'baseUrl: Missing value' )
        } else if( typeof baseUrl !== 'string' ) {
            struct.messages.push( 'baseUrl: Must be a string' )
        } else if( !baseUrl.startsWith( 'http://' ) && !baseUrl.startsWith( 'https://' ) ) {
            struct.messages.push( 'baseUrl: Must start with http:// or https://' )
        }

        if( routePath === undefined || routePath === null ) {
            struct.messages.push( 'routePath: Missing value' )
        } else if( typeof routePath !== 'string' ) {
            struct.messages.push( 'routePath: Must be a string' )
        } else if( !routePath.startsWith( '/' ) ) {
            struct.messages.push( 'routePath: Must start with /' )
        }

        if( struct.messages.length === 0 ) {
            struct.status = true
        }

        return struct
    }


    static validationTestBearerStreamable( { baseUrl, routePath, bearerToken } ) {
        const struct = { status: false, messages: [] }

        const { status: baseValidation, messages: baseMessages } = this.validationTestStreamableRoute( { baseUrl, routePath } )
        struct.messages.push( ...baseMessages )

        if( bearerToken === undefined || bearerToken === null ) {
            struct.messages.push( 'bearerToken: Missing value' )
        } else if( typeof bearerToken !== 'string' ) {
            struct.messages.push( 'bearerToken: Must be a string' )
        } else if( bearerToken.length < 8 ) {
            struct.messages.push( 'bearerToken: Must be at least 8 characters long' )
        }

        if( struct.messages.length === 0 ) {
            struct.status = true
        }

        return struct
    }


    static validationTestOAuthStreamable( { baseUrl, routePath, oauth21Config, browserTimeout = 90000, silent = false } ) {
        const struct = { status: false, messages: [] }

        const { status: baseValidation, messages: baseMessages } = this.validationTestStreamableRoute( { baseUrl, routePath } )
        struct.messages.push( ...baseMessages )

        if( oauth21Config === undefined || oauth21Config === null ) {
            struct.messages.push( 'oauth21Config: Missing value' )
        } else if( typeof oauth21Config !== 'object' ) {
            struct.messages.push( 'oauth21Config: Must be an object' )
        } else {
            const requiredFields = [
                [ 'providerUrl',    oauth21Config.providerUrl,    'string' ],
                [ 'clientId',       oauth21Config.clientId,       'string' ],
                [ 'clientSecret',   oauth21Config.clientSecret,   'string' ],
                [ 'organizationId', oauth21Config.organizationId, 'string' ],
                [ 'mcpId',          oauth21Config.mcpId,          'string' ]
            ]
                .forEach( ( [ key, value, type ] ) => {
                    if( value === undefined || value === null ) {
                        struct.messages.push( `oauth21Config.${key}: Missing value` )
                    } else if( typeof value !== type ) {
                        struct.messages.push( `oauth21Config.${key}: Must be a ${type}` )
                    } else if( key === 'providerUrl' && !value.startsWith( 'http' ) ) {
                        struct.messages.push( `oauth21Config.${key}: Must be a valid URL starting with http` )
                    }
                } )
        }

        if( typeof browserTimeout !== 'number' ) {
            struct.messages.push( 'browserTimeout: Must be a number' )
        } else if( browserTimeout < 10000 ) {
            struct.messages.push( 'browserTimeout: Must be at least 10000ms (10 seconds)' )
        }

        if( typeof silent !== 'boolean' ) {
            struct.messages.push( 'silent: Must be a boolean' )
        }

        if( struct.messages.length === 0 ) {
            struct.status = true
        }

        return struct
    }


    static error( { messages } ) {
        const errorMessage = `Validation failed:\n- ${messages.join( '\n- ' )}`
        throw new Error( errorMessage )
    }
}


export { TestValidation }