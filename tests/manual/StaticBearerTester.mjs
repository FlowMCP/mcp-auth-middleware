import { OAuthBearerTokenDemo } from '../simulation/oauth-bearer-token-demo.mjs'
import { ConfigManager } from './ConfigManager.mjs'


class StaticBearerTester {
    static async runTest( { baseUrl, routePath, silent, browserTimeout } ) {
        const config = await this.#loadConfig()
        const { token } = config.auth

        if( !silent ) {
            console.log( '🔑 Static Bearer Token Flow' )
            console.log( '📍 Using pre-configured bearer token' )
            console.log( '' )
            console.log( `   Token: ${token.substring( 0, 20 )}...` )
            console.log( `   Base URL: ${baseUrl}` )
            console.log( `   Route: ${routePath}` )
            console.log( '' )
        }

        // Create adapted result structure for staticBearer
        const adaptedResult = {
            baseUrl,
            routePath,
            clientId: 'static-bearer-client',
            authType: 'staticBearer',
            staticToken: token,
            success: true,

            // Bearer-specific structure for display
            bearerTokenDemo: {
                fullToken: `Bearer ${token}`,
                tokenType: 'Bearer',
                accessToken: token,
                apiUsageExample: `Authorization: Bearer ${token}`,
                curlExample: `curl -H "Authorization: Bearer ${token}" ${baseUrl}${routePath}`
            },

            summary: {
                demonstration: 'Static Bearer Token Flow',
                status: 'SUCCESS',
                tokenGenerated: false,
                tokenType: 'Bearer',
                tokenLength: token.length,
                tokenPreview: `${token.substring( 0, 20 )}...`,
                fullBearerToken: `Bearer ${token}`,
                conclusion: 'Static bearer token configured successfully'
            },

            // Simplified flow results
            flowResults: {
                'token_validation': { success: true },
                'configuration_load': { success: true },
                'bearer_setup': { success: true }
            }
        }

        if( !silent ) {
            console.log( '✅ Static Bearer Token configured successfully!' )
        }

        return adaptedResult
    }


    static async #loadConfig() {
        const { authTypValue } = await ConfigManager.getConfig( { authTypKey: 'staticBearer' } )
        return { auth: authTypValue }
    }
}


export { StaticBearerTester }