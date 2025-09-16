import { OAuth21ScalekitProvider } from './src/authTypes/oauth21_scalekit/OAuth21ScalekitProvider.mjs'
import { OAuth21Auth0Provider } from './src/authTypes/oauth21_auth0/OAuth21Auth0Provider.mjs'

console.log('🧪 PROOF: Provider-Specific Endpoints Working\n')

// ScaleKit Provider Test
const scalekitProvider = new OAuth21ScalekitProvider({ silent: true })
const scalekitResult = scalekitProvider.getDiscoveryMetadata({
    config: { providerUrl: 'https://auth.flowmcp.org', scope: 'tools:read' }
})

console.log('📋 ScaleKit Provider:')
console.log(`   ✅ /oauth/authorize: ${scalekitResult.metadata.authorization_endpoint}`)

// Auth0 Provider Test
const auth0Provider = new OAuth21Auth0Provider({ silent: true })
const auth0Result = auth0Provider.getDiscoveryMetadata({
    config: { providerUrl: 'https://tenant.auth0.com', scope: 'openid profile' }
})

console.log('📋 Auth0 Provider:')
console.log(`   ✅ /authorize: ${auth0Result.metadata.authorization_endpoint}`)

// Proof Test
const scalekitCorrect = scalekitResult.metadata.authorization_endpoint.endsWith('/oauth/authorize')
const auth0Correct = auth0Result.metadata.authorization_endpoint.endsWith('/authorize') &&
                     !auth0Result.metadata.authorization_endpoint.includes('/oauth/authorize')

console.log('\n🎯 VERIFICATION:')
console.log(`   ScaleKit /oauth/authorize: ${scalekitCorrect ? '✅ CORRECT' : '❌ WRONG'}`)
console.log(`   Auth0 /authorize: ${auth0Correct ? '✅ CORRECT' : '❌ WRONG'}`)
console.log(`   Problem SOLVED: ${scalekitCorrect && auth0Correct ? '✅ YES' : '❌ NO'}`)