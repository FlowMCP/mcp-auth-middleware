import { OAuth21ScalekitPuppeteerTester } from './OAuth21ScalekitPuppeteerTester.mjs'
import { ConfigManager } from './ConfigManager.mjs'


class RemoteTesting {
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


    static validationArgv( { remoteUrl, remoteUrls } ) {
        const struct = { status: false, messages: [] }

        if( !remoteUrl ) {
            struct.messages.push( 'Missing remoteUrl parameter' )
        } else if( !remoteUrls.includes( remoteUrl ) ) {
            struct.messages.push( `Invalid remoteUrl "${remoteUrl}". Valid URLs: ${remoteUrls.join(', ')}` )
        }

        if( struct.messages.length === 0 ) {
            struct.status = true
        }

        return struct
    }


    static async start( { remoteUrl } ) {
        this.#printStart()

        const { baseUrl, port, routePath } = this.#parseRemoteUrl( { remoteUrl } )
        const { config } = await ConfigManager.getRemoteConfig( { baseUrl, port, routePath } )
        const { silent, browserTimeout } = config

        const serverAvailable = await this.#checkRemoteServerAvailability( { remoteUrl } )
        if( !serverAvailable ) {
            throw new Error( `Remote server not available at: ${remoteUrl}` )
        }

        console.log( `Remote server is available at ${remoteUrl}` )
        console.log( 'Starting OAuth21 ScaleKit authentication flow' )

        const fullBaseUrl = port ? `${baseUrl}:${port}` : baseUrl
        const result = await OAuth21ScalekitPuppeteerTester
            .runTest( { baseUrl: fullBaseUrl, routePath, silent, browserTimeout } )

        this.#printOAuth21Result( { result } )

        return result
    }


    static #parseRemoteUrl( { remoteUrl } ) {
        const url = new URL( remoteUrl )
        const baseUrl = `${url.protocol}//${url.hostname}`
        const port = url.port || null
        const routePath = url.pathname

        return { baseUrl, port, routePath }
    }


    static async #checkRemoteServerAvailability( { remoteUrl } ) {
        try {
            const controller = new AbortController()
            const timeoutId = setTimeout( () => controller.abort(), 10000 )

            const response = await fetch( remoteUrl, {
                method: 'HEAD',
                signal: controller.signal
            } )

            clearTimeout( timeoutId )
            return true
        } catch( error ) {
            console.error( `Remote server check failed: ${error.message}` )
            return false
        }
    }


    static #printOAuth21Result( { result } ) {
        console.log( '✅ Remote Test completed successfully!' )
        console.log( '' )
        console.log( '📊 Result Summary:' )
        console.log( `   Base URL: ${result.baseUrl}` )
        console.log( `   Route: ${result.routePath}` )
        console.log( `   Client ID: ${result.clientId}` )
        console.log( '' )

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

        console.log( '📋 Flow Results:' )
        Object.entries( result.flowResults )
            .forEach( ( [ step, stepResult ] ) => {
                const success = stepResult.success !== false
                const icon = success ? '✅' : '❌'
                console.log( `   ${icon} ${step}: ${success ? 'SUCCESS' : 'FAILED'}` )
            } )

        console.log( '' )
        console.log( '🎯 Remote OAuth21 ScaleKit flow completed successfully!' )
    }


    static #printStart() {
        console.log( '🚀 Starting Remote OAuth21 ScaleKit Test' )
        console.log( '📋 This test will:' )
        console.log( '   1. Check remote server availability' )
        console.log( '   2. Perform OAuth discovery from remote URL' )
        console.log( '   3. Register client using discovery results' )
        console.log( '   4. Prepare authorization using real metadata' )
        console.log( '   5. Open browser for real authorization flow' )
        console.log( '   6. Exchange real authorization code for tokens' )
        console.log( '   7. Validate tokens using real userinfo endpoint' )
        console.log( '   8. Send MCP list_tools request to fetch available tools' )
        console.log( '   9. Call the first tool from the list using MCP tools/call' )
        console.log( '' )
    }
}


export { RemoteTesting }