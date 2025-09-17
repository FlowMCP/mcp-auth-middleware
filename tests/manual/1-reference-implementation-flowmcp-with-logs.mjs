import cors from 'cors'
import { DeployAdvanced } from 'flowmcpServers'
import { McpAuthMiddleware } from '../../src/index.mjs'
import { ConfigManager } from './ConfigManager.mjs'


console.log('🔧 Loading configuration...')

// Get configuration for different auth types
const { config: staticConfig, authTypValue: staticAuth } = await ConfigManager.getConfig({
    authTypKey: 'staticBearer'
})

const { config: scalekitConfig, authTypValue: scalekitAuth } = await ConfigManager.getConfig({
    authTypKey: 'oauth21_scalekit'
})

const { silent, baseUrl, forceHttps } = staticConfig

console.log(`📍 Base URL: ${baseUrl}`)
console.log(`🔒 Force HTTPS: ${forceHttps}`)
console.log(`🔇 Silent Mode: ${silent}`)
console.log('')

console.log('🎯 Creating middleware with new API structure...')

// Create middleware with mixed auth types
const oauthMiddleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: staticAuth.token,
        attachedRoutes: ['/api', '/tools']
    },
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/oauth', '/secure'],
        options: {
            providerUrl: scalekitAuth.providerUrl,
            mcpId: scalekitAuth.mcpId,
            clientId: scalekitAuth.clientId,
            clientSecret: scalekitAuth.clientSecret,
            resource: scalekitAuth.resource,
            scope: scalekitAuth.scope
        }
    },
    silent: false, // Enable detailed logging
    baseUrl,
    forceHttps
})

console.log('✅ OAuth Middleware created successfully')
console.log(`📊 Protected Routes: ${oauthMiddleware.getRoutes().join(', ')}`)
console.log('')

console.log('📊 Loading schemas...')

// Configure FlowMCP schemas for different routes
const objectOfSchemaArrays = {
    '/api': await import('../schemas/api-schemas.mjs').then(m => {
        console.log('✅ Loaded /api schemas')
        return m.arrayOfSchemas
    }).catch(() => {
        console.log('⚠️  No schemas found for /api')
        return []
    }),
    '/tools': await import('../schemas/tool-schemas.mjs').then(m => {
        console.log('✅ Loaded /tools schemas')
        return m.arrayOfSchemas
    }).catch(() => {
        console.log('⚠️  No schemas found for /tools')
        return []
    }),
    '/oauth': await import('../schemas/oauth-schemas.mjs').then(m => {
        console.log('✅ Loaded /oauth schemas')
        return m.arrayOfSchemas
    }).catch(() => {
        console.log('⚠️  No schemas found for /oauth')
        return []
    }),
    '/secure': await import('../schemas/secure-schemas.mjs').then(m => {
        console.log('✅ Loaded /secure schemas')
        return m.arrayOfSchemas
    }).catch(() => {
        console.log('⚠️  No schemas found for /secure')
        return []
    })
}

console.log('✅ All schemas loaded successfully')
console.log('')

// Configure routes for FlowMCP
const arrayOfRoutes = [
    {
        routePath: '/api',
        protocol: '/streamable',
        bearerToken: 'required' // StaticBearer route
    },
    {
        routePath: '/tools',
        protocol: '/streamable',
        bearerToken: 'required' // StaticBearer route
    },
    {
        routePath: '/oauth',
        protocol: '/streamable',
        bearerToken: null // OAuth21 route
    },
    {
        routePath: '/secure',
        protocol: '/streamable',
        bearerToken: null // OAuth21 route
    }
]

console.log('🚀 Initializing FlowMCP server...')

const { app, mcps, events, argv, server } = DeployAdvanced
    .init({ silent: false })

console.log('✅ FlowMCP server initialized')

// Enable trust proxy for correct protocol detection behind reverse proxies
app.set('trust proxy', true)
console.log('✅ Trust proxy enabled')

// CORS for Inspector access
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'mcp-protocol-version']
}))
console.log('✅ CORS middleware applied')

// Apply OAuth middleware
app.use(oauthMiddleware.router())
console.log('✅ OAuth middleware applied')

const { port } = staticConfig
const rootUrl = baseUrl

console.log('')
console.log('🎬 Starting server...')

DeployAdvanced
    .start({ arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port })

console.log('')
console.log('🎉 Reference Implementation Started with Detailed Logging!')
console.log('=========================================================')
console.log(`🌐 Base URL: ${baseUrl}:${port}`)
console.log(`🔐 Auth Types: StaticBearer + OAuth21 ScaleKit`)
console.log(`📍 Protected Routes:`)
console.log(`   📘 StaticBearer: /api, /tools (Bearer ${staticAuth.token.substring(0, 10)}...)`)
console.log(`   🔑 OAuth21:     /oauth, /secure (ScaleKit ${scalekitAuth.mcpId})`)
console.log(`📚 Discovery: ${baseUrl}:${port}/.well-known/`)
console.log(`📊 Route Config Details:`)
arrayOfRoutes.forEach(route => {
    console.log(`   ${route.routePath}${route.protocol} - Bearer: ${route.bearerToken || 'OAuth21'}`)
})
console.log('')
console.log('💡 Test Commands:')
console.log(`   StaticBearer: curl -H "Authorization: Bearer ${staticAuth.token}" ${baseUrl}:${port}/api/streamable`)
console.log(`   OAuth21:      Open ${baseUrl}:${port}/oauth/auth/login in browser`)
console.log('')