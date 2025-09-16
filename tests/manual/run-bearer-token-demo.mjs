import { OAuthBearerTokenDemo } from '../simulation/oauth-bearer-token-demo.mjs'


async function checkServerAvailability( baseUrl ) {
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
        console.error( `❌ Server not reachable at ${baseUrl}` )
        console.error( `   Error: ${error.message}` )
        console.error( '' )
        console.error( '   Please start the server first:' )
        console.error( '   npm run dev' )
        console.error( '   or' )
        console.error( '   node server.mjs' )
        console.error( '' )
        return false
    }
}


async function runBearerTokenDemo() {
    console.log( '🚀 OAuth Bearer Token Demonstration' )
    console.log( '📋 This demo will:' )
    console.log( '   1. Perform real OAuth discovery' )
    console.log( '   2. Register client with real endpoints' )
    console.log( '   3. Simulate authorization (bypass external IdP)' )
    console.log( '   4. Exchange authorization code for bearer token' )
    console.log( '   5. Display the working bearer token' )
    console.log( '' )

    const baseUrl = 'http://localhost:3001'

    // Check server availability first
    console.log( `🔍 Checking server availability at ${baseUrl}...` )
    const serverAvailable = await checkServerAvailability( baseUrl )

    if( !serverAvailable ) {
        process.exit( 1 )
    }

    console.log( '✅ Server is reachable, proceeding with demonstration...' )
    console.log( '' )

    try {
        const result = await OAuthBearerTokenDemo.demonstrateBearerToken( {
            baseUrl: baseUrl,
            routePath: '/scalekit-route',
            silent: false
        } )

        console.log( '' )
        console.log( '🎯 DEMONSTRATION COMPLETED SUCCESSFULLY!' )
        console.log( '' )
        console.log( '📊 Final Summary:' )
        console.log( `   Demonstration: ${result.summary.demonstration}` )
        console.log( `   Status: ${result.summary.status}` )
        console.log( `   Token Generated: ${result.summary.tokenGenerated}` )
        console.log( `   Token Type: ${result.summary.tokenType}` )
        console.log( `   Token Length: ${result.summary.tokenLength} characters` )
        console.log( `   Token Preview: ${result.summary.tokenPreview}` )
        console.log( '' )
        console.log( '🔑 FULL BEARER TOKEN:' )
        console.log( `   ${result.summary.fullBearerToken}` )
        console.log( '' )
        console.log( '💡 Ready to use in API calls!' )
        console.log( `   Example: ${result.bearerTokenDemo.curlExample}` )

        return result

    } catch( error ) {
        console.error( '❌ Bearer Token Demonstration failed:' )
        console.error( error.message )
        console.error( '' )
        console.error( 'Stack trace:' )
        console.error( error.stack )

        process.exit( 1 )
    }
}


// Run if called directly
if( import.meta.url === `file://${process.argv[1]}` ) {
    runBearerTokenDemo()
}


export { runBearerTokenDemo }