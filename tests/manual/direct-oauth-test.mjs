#!/usr/bin/env node

import { OAuthFlowHandler } from '../../src/helpers/OAuthFlowHandler.mjs'


console.log('🔍 Direct OAuth URL generation test...\n')

// Simulate the exact configuration that would be passed to OAuthFlowHandler
const testConfig = {
    authType: 'oauth21_auth0',
    providerUrl: 'https://auth.flowmcp.org',
    realm: 'etherscan-ping-sse-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'https://server.example.com/api/auth/callback',
    authFlow: 'authorization_code',
    requiredScopes: ['openid', 'profile', 'email'],
    forceHttps: true,
    resourceUri: 'https://api.flowmcp.org',
    // These should be the correctly generated Auth0 endpoints
    authorizationEndpoint: 'https://auth.flowmcp.org/authorize',
    tokenEndpoint: 'https://auth.flowmcp.org/oauth/token',
    deviceAuthorizationEndpoint: 'https://auth.flowmcp.org/oauth/device/code'
}

// Test the multi-realm creation (this is how McpAuthMiddleware uses it)
const routes = {
    '/api': testConfig
}

const baseRedirectUri = 'https://server.example.com'

try {
    console.log('🔧 Creating OAuthFlowHandler with test configuration...')

    const handler = OAuthFlowHandler.createForMultiRealm( {
        routes,
        baseRedirectUri,
        silent: false
    } )

    console.log('✅ Handler created successfully!\n')

    // Test OAuth flow initiation
    console.log('🚀 Initiating authorization code flow...')

    const result = handler.initiateAuthorizationCodeFlowForRoute( {
        routePath: '/api',
        scopes: ['openid', 'profile', 'email']
    } )

    console.log('\n📍 Generated Authorization URL:')
    console.log(result.authorizationUrl)

    const urlParts = result.authorizationUrl.split('?')
    const baseUrl = urlParts[0]

    console.log('\n🔍 Analysis:')
    console.log('   Base URL: ' + baseUrl)

    if( baseUrl === 'https://auth.flowmcp.org/authorize' ) {
        console.log('   ✅ SUCCESS: Correct Auth0 URL structure!')
    } else if( baseUrl.includes('/realms/') ) {
        console.log('   ❌ ERROR: Still using Keycloak URL structure!')
        console.log('   Expected: https://auth.flowmcp.org/authorize')
    } else {
        console.log('   ❓ UNKNOWN: Unexpected URL structure')
    }

    console.log('\n📋 Full URL parameters:')
    if( urlParts[1] ) {
        const params = new URLSearchParams(urlParts[1])
        params.forEach( ( value, key ) => {
            console.log(`   ${key}: ${value}`)
        } )
    }

} catch( error ) {
    console.log('❌ Error during test:')
    console.log('   ' + error.message)
    if( error.stack ) {
        console.log('\n📄 Stack trace:')
        console.log(error.stack)
    }
}

console.log('\n🏁 Direct OAuth test complete!')