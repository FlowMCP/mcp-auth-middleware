import { spawn } from 'child_process'
import { OAuth21ScalekitPuppeteerTester } from './OAuth21ScalekitPuppeteerTester.mjs'
import { StaticBearerTester } from './StaticBearerTester.mjs'
import { ConfigManager } from './ConfigManager.mjs'


class Testing {
    static parseArgv( { argv } ) {
        const args = argv.slice( 2 )
        const params = {}

        args.forEach( ( arg ) => {
            const [ key, value ] = arg.split( '=' )
            if( key && value ) {
                params[ key ] = value
            }
        } )

        return params
    }


    static validationArgv( { authTypKey, serverPath, authTypes, serverPaths } ) {
        const { status, messages } = [
            [ authTypKey, authTypes   ],
            [ serverPath, serverPaths ]
        ]
            .reduce( ( acc, [ paramValue, validValues ], index, arr ) => {
                if( !paramValue ) {
                    acc.messages.push( `Missing parameter.` )
                }
                else if( !validValues.includes( paramValue ) ) {
                    acc.messages.push( `Invalid parameter value "${paramValue}". Valid values: ${validValues.join(', ')}` )
                }
                if( index === arr.length - 1 && acc.messages.length === 0 ) {
                    acc.status = true
                }
                return acc
            }, { status: false, messages: [] } )

        return { status, messages }
    }


    static async start( { authTypKey = 'oauth21_scalekit', serverPath = 'tests/manual/test-mcp-server.mjs' } = {} ) {
        this.#printStart()
        const { config } = await ConfigManager.getConfig( { authTypKey } )
        const { baseUrl, port, routePath, silent, browserTimeout } = config
        const fullBaseUrl = `${baseUrl}:${port}`

        const serverProcess = await this.#ensureServer( { fullBaseUrl, serverPath } )

        let result
        switch( authTypKey ) {
            case 'oauth21_scalekit':
                console.log( 'Using OAuth21 ScaleKit authentication flow' )
                result = await OAuth21ScalekitPuppeteerTester
                    .runTest( { baseUrl: fullBaseUrl, routePath, silent, browserTimeout } )
                this.#printOAuth21Result( { result } )
                break
            case 'staticBearer':
                console.log( 'Using Static Bearer Token authentication flow' )
                result = await StaticBearerTester
                    .runTest( { baseUrl: fullBaseUrl, routePath, silent, browserTimeout } )
                this.#printBearerResult( { result } )
                break
            default:
                throw new Error( `Unsupported authTypKey: ${authTypKey}` )
        }

        this.#cleanup( { serverProcess } )

        return result
    }



    static async #ensureServer( { fullBaseUrl, serverPath } ) {
        console.log( `Checking server availability at ${fullBaseUrl}...` )
        const serverAvailable = await this.#checkServerAvailability( { baseUrl: fullBaseUrl } )

        if( serverAvailable ) {
            console.log( 'Server is already running, proceeding with test...' )
            return null
        }

        console.log( 'Starting MCP server...' )
        const serverProcess = await this.#startServer( { serverPath } )
        console.log( 'Server started successfully!' )

        return serverProcess
    }


    static async #checkServerAvailability( { baseUrl } ) {
        try {
            const controller = new AbortController()
            const timeoutId = setTimeout( () => controller.abort(), 5000 )

            const response = await fetch( baseUrl, {
                method: 'HEAD',
                signal: controller.signal
            } )

            clearTimeout( timeoutId )
            return true
        } catch( error ) {
            return false
        }
    }


    static async #startServer( { serverPath } ) {
        const serverProcess = spawn( 'node', [ serverPath ], {
            stdio: 'pipe',
            detached: false
        } )

        return new Promise( ( resolve, reject ) => {
            let serverReady = false
            const timeout = setTimeout( () => {
                if( !serverReady ) {
                    serverProcess.kill()
                    reject( new Error( 'Server startup timeout after 30 seconds' ) )
                }
            }, 30000 )

            serverProcess.stdout.on( 'data', ( data ) => {
                const output = data.toString()
                console.log( `[Server] ${output.trim()}` )

                if( output.includes( 'MCP Discovery endpoints registered' ) && !serverReady ) {
                    serverReady = true
                    clearTimeout( timeout )
                    console.log( 'Server is ready!' )

                    setTimeout( () => {
                        resolve( serverProcess )
                    }, 5000 )
                }
            } )

            serverProcess.stderr.on( 'data', ( data ) => {
                console.error( `[Server Error] ${data.toString().trim()}` )
            } )

            serverProcess.on( 'error', ( error ) => {
                clearTimeout( timeout )
                reject( new Error( `Failed to start server: ${error.message}` ) )
            } )

            serverProcess.on( 'exit', ( code ) => {
                clearTimeout( timeout )
                if( !serverReady ) {
                    reject( new Error( `Server exited early with code ${code}` ) )
                }
            } )
        } )
    }


    static #cleanup( { serverProcess } ) {
        if( serverProcess ) {
            console.log( '' )
            console.log( 'Stopping server...' )
            serverProcess.kill()
            console.log( 'Server stopped.' )
        }
    }


    static #printOAuth21Result( { result } ) {
        console.log( '✅ Test completed successfully!' )
        console.log( '' )
        console.log( '📊 Result Summary:' )
        console.log( `   Base URL: ${result.baseUrl}` )
        console.log( `   Route: ${result.routePath}` )
        console.log( `   Client ID: ${result.clientId}` )
        console.log( '' )

        // Display request chain
        if( result.requestChain ) {
            console.log( '🔗 Request Chain:' )
            Object.entries( result.requestChain )
                .forEach( ( [ step, details ] ) => {
                    console.log( `   ${step}:` )
                    console.log( `     Input: ${JSON.stringify( details.input )}` )
                    console.log( `     Derivation: ${details.derivation}` )
                    console.log( `     Output: ${JSON.stringify( details.output )}` )
                    console.log( '' )
                } )
        }

        // Display flow results summary
        console.log( '📋 Flow Results:' )
        Object.entries( result.flowResults )
            .forEach( ( [ step, stepResult ] ) => {
                const success = stepResult.success !== false
                const icon = success ? '✅' : '❌'
                console.log( `   ${icon} ${step}: ${success ? 'SUCCESS' : 'FAILED'}` )
            } )

        console.log( '' )
        console.log( '🎯 Full result object available in returned value' )
    }


    static #printBearerResult( { result } ) {
        console.log( '✅ Bearer Token Test completed successfully!' )
        console.log( '' )
        console.log( '📊 Result Summary:' )
        console.log( `   Base URL: ${result.baseUrl}` )
        console.log( `   Route: ${result.routePath}` )
        console.log( `   Auth Type: ${result.authType}` )
        console.log( '' )

        // Display bearer token details
        if( result.summary ) {
            console.log( '🔑 Bearer Token Details:' )
            console.log( `   Status: ${result.summary.status}` )
            console.log( `   Token Type: ${result.summary.tokenType}` )
            console.log( `   Token Length: ${result.summary.tokenLength} characters` )
            console.log( `   Token Preview: ${result.summary.tokenPreview}` )
            console.log( '' )
            console.log( '🔐 Full Bearer Token:' )
            console.log( `   ${result.summary.fullBearerToken}` )
            console.log( '' )
        }

        // Display usage examples
        if( result.bearerTokenDemo ) {
            console.log( '💡 Usage Examples:' )
            console.log( `   API Usage: ${result.bearerTokenDemo.apiUsageExample}` )
            console.log( `   Curl Command: ${result.bearerTokenDemo.curlExample}` )
            console.log( '' )
        }

        // Display flow results summary
        console.log( '📋 Flow Results:' )
        Object.entries( result.flowResults )
            .forEach( ( [ step, stepResult ] ) => {
                const success = stepResult.success !== false
                const icon = success ? '✅' : '❌'
                console.log( `   ${icon} ${step}: ${success ? 'SUCCESS' : 'FAILED'}` )
            } )

        console.log( '' )
        console.log( '🎯 Ready to use in API calls!' )
    }


    static #printStart() {
        console.log( '🚀 Starting OAuth21 ScaleKit Puppeteer Test' )
        console.log( '📋 This test will:' )
        console.log( '   1. Perform OAuth discovery from base URL' )
        console.log( '   2. Register client using discovery results' )
        console.log( '   3. Prepare authorization using real metadata' )
        console.log( '   4. Open browser for real authorization flow' )
        console.log( '   5. Exchange real authorization code for tokens' )
        console.log( '   6. Validate tokens using real userinfo endpoint' )
        console.log( '   7. Send MCP list_tools request to fetch available tools' )
        console.log( '   8. Call the first tool from the list using MCP tools/call' )
        console.log( '' )
    }
}


export { Testing }