import { OAuthMiddlewareTester } from './../../src/index.mjs'
import { ConfigExamples } from './ConfigExamples.mjs'


class RemoteTestRunner {
    static parseArguments( { argv } ) {
        // Extract routeType parameter
        const routeTypeArg = argv.find( arg => arg.startsWith( '--routeType=' ) )
        if( !routeTypeArg ) {
            throw new Error( 'Missing --routeType parameter' )
        }
        const routeType = routeTypeArg.split( '=' )[1]

        // Check for --dynamic flag
        const useDynamic = argv.includes( '--dynamic' ) || argv.includes( '--dcr' )

        // Extract URL (last parameter)
        const url = argv[argv.length - 1]
        if( !url || url.startsWith( '--' ) ) {
            throw new Error( 'Missing URL parameter (must be last argument)' )
        }

        return { routeType, url, useDynamic }
    }


    static parseUrl( { url } ) {
        try {
            const parsedUrl = new URL( url )
            const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`
            const routePath = parsedUrl.pathname || '/ping'

            return { baseUrl, routePath }
        } catch( error ) {
            throw new Error( `Invalid URL format: ${url}. Please provide a valid URL like: https://api.example.com/api/tools` )
        }
    }


    static validateRouteType( { routeType } ) {
        const validRouteTypes = ['free-route', 'static-bearer', 'oauth']
        if( !validRouteTypes.includes( routeType ) ) {
            throw new Error( `Invalid routeType: ${routeType}. Valid values: ${validRouteTypes.join(', ')}` )
        }
    }


    static displayTestInfo( { routeType, baseUrl, routePath, originalUrl, useDynamic } ) {
        console.log( '🔍 Remote Test Configuration:' )
        console.log( '═'.repeat( 50 ) )
        console.log( `   Route Type:  ${routeType}` )
        console.log( `   Original URL: ${originalUrl}` )
        console.log( `   Base URL:    ${baseUrl}` )
        console.log( `   Route Path:  ${routePath}` )
        if( useDynamic && routeType === 'oauth' ) {
            console.log( `   DCR Mode:    ✅ Dynamic Client Registration` )
        }
        console.log( '═'.repeat( 50 ) )
        console.log( '' )
    }


    static async runTest( { routeType, baseUrl, routePath, useDynamic } ) {
        // Only load config if not using dynamic registration
        const config = ( !useDynamic && routeType !== 'free-route' ) ?
            new ConfigExamples( {
                envPath: './../../.auth.env',
                routePath,
                silent: false
            } ) : null

        switch( routeType ) {
            case 'free-route':
                console.log( '🌐 Testing Free Route (no authentication required)...' )
                return await OAuthMiddlewareTester.testStreamableRoute( {
                    baseUrl,
                    routePath,
                    timeout: 30000,
                    expectedStatus: 200
                } )

            case 'static-bearer':
                console.log( '🔐 Testing Static Bearer Token authentication...' )
                if( !config ) {
                    throw new Error( 'Static Bearer requires .auth.env configuration' )
                }
                const { bearerSecretToken } = config.getState()
                return await OAuthMiddlewareTester.testBearerStreamable( {
                    baseUrl,
                    routePath,
                    bearerToken: bearerSecretToken,
                    timeout: 30000,
                    testUnauthorized: true,
                    expectedUnauthorizedStatus: 401
                } )

            case 'oauth':
                if( useDynamic ) {
                    console.log( '🔑 Testing OAuth 2.1 with Dynamic Client Registration...' )
                    console.log( '   🚀 No pre-configured credentials needed!' )
                    return await OAuthMiddlewareTester.testOAuthStreamable( {
                        baseUrl,
                        routePath,
                        oauth21Config: null, // Signal to use DCR
                        browserTimeout: 90000,
                        silent: false,
                        testUnauthorized: true,
                        expectedUnauthorizedStatus: 401,
                        useDynamicRegistration: true
                    } )
                } else {
                    console.log( '🔑 Testing OAuth 2.1 ScaleKit authentication...' )
                    if( !config ) {
                        throw new Error( 'OAuth requires configuration. Use --dynamic for DCR or provide .auth.env' )
                    }
                    const { oauth21Config } = config.getMcpAuthScaleKitConfig()
                    return await OAuthMiddlewareTester.testOAuthStreamable( {
                        baseUrl,
                        routePath,
                        oauth21Config,
                        browserTimeout: 90000,
                        silent: false,
                        testUnauthorized: true,
                        expectedUnauthorizedStatus: 401
                    } )
                }

            default:
                throw new Error( `Unsupported routeType: ${routeType}` )
        }
    }


    static async main() {
        try {
            // Parse command line arguments
            const { routeType, url, useDynamic } = this.parseArguments( { argv: process.argv } )
            this.validateRouteType( { routeType } )

            // Parse and validate URL
            const { baseUrl, routePath } = this.parseUrl( { url } )

            // Display test configuration
            this.displayTestInfo( { routeType, baseUrl, routePath, originalUrl: url, useDynamic } )

            // Run the test
            const result = await this.runTest( { routeType, baseUrl, routePath, useDynamic } )

            if( result.success ) {
                console.log( '\n✅ Remote test completed successfully!' )
                console.log( `   Test Type: ${routeType}` )
                console.log( `   Target: ${baseUrl}${routePath}` )
                process.exit( 0 )
            } else {
                console.log( '\n❌ Remote test failed!' )
                console.log( `   Error: ${result.error || 'Unknown error'}` )
                process.exit( 1 )
            }

        } catch( error ) {
            console.log( '\n❌ Remote Test Error:' )
            console.log( `   ${error.message}` )
            console.log( '' )
            console.log( '📋 Usage Examples:' )
            console.log( '   npm run test:remote:free https://api.example.com/api/tools' )
            console.log( '   npm run test:remote:bearer https://api.example.com/api/tools' )
            console.log( '   npm run test:remote:oauth https://api.example.com/api/tools' )
            process.exit( 1 )
        }
    }
}


// Run the remote test
RemoteTestRunner.main()