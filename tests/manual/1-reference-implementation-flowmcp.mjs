import cors from 'cors'
import { DeployAdvanced } from 'flowmcpServers'
import { McpAuthMiddleware } from '../../src/index.mjs'
import { ConfigManager } from './ConfigManager.mjs'


// Get configuration for different auth types
const { config: staticConfig, authTypValue: staticAuth } = await ConfigManager.getConfig({
    authTypKey: 'staticBearer'
})

const { config: scalekitConfig, authTypValue: scalekitAuth } = await ConfigManager.getConfig({
    authTypKey: 'oauth21_scalekit'
})

const { silent, baseUrl, forceHttps } = staticConfig

// Create middleware with new API structure
// Example 1: StaticBearer only
const staticBearerMiddleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: staticAuth.token,
        attachedRoutes: ['/static-route']
    },
    silent,
    baseUrl,
    forceHttps
})

// Example 2: OAuth21 ScaleKit only
const scalekitMiddleware = await McpAuthMiddleware.create({
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/scalekit-route'],
        options: {
            providerUrl: scalekitAuth.providerUrl,
            mcpId: scalekitAuth.mcpId,
            clientId: scalekitAuth.clientId,
            clientSecret: scalekitAuth.clientSecret,
            resource: scalekitAuth.resource,
            scope: scalekitAuth.scope
        }
    },
    silent,
    baseUrl,
    forceHttps
})

// Example 3: Mixed auth types (both StaticBearer and OAuth21)
const mixedMiddleware = await McpAuthMiddleware.create({
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
    silent,
    baseUrl,
    forceHttps
})

// Use the mixed middleware for demonstration
const oauthMiddleware = mixedMiddleware

// Configure FlowMCP schemas for different routes
const objectOfSchemaArrays = {
    '/api': await import('../schemas/api-schemas.mjs').then(m => m.arrayOfSchemas).catch(() => []),
    '/tools': await import('../schemas/tool-schemas.mjs').then(m => m.arrayOfSchemas).catch(() => []),
    '/oauth': await import('../schemas/oauth-schemas.mjs').then(m => m.arrayOfSchemas).catch(() => []),
    '/secure': await import('../schemas/secure-schemas.mjs').then(m => m.arrayOfSchemas).catch(() => [])
}

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

const { app, mcps, events, argv, server } = DeployAdvanced
    .init({ silent })

// Enable trust proxy for correct protocol detection behind reverse proxies
app.set('trust proxy', true)

// CORS for Inspector access
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'mcp-protocol-version']
}))

// Apply OAuth middleware
app.use(oauthMiddleware.router())

const { port } = staticConfig
const rootUrl = baseUrl

DeployAdvanced
    .start({ arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port })

console.log('\n🎉 Reference Implementation Started!')
console.log('=====================================')
console.log(`🌐 Base URL: ${baseUrl}:${port}`)
console.log(`🔐 Auth Types: StaticBearer + OAuth21 ScaleKit`)
console.log(`📍 Protected Routes:`)
console.log(`   📘 StaticBearer: /api, /tools`)
console.log(`   🔑 OAuth21:     /oauth, /secure`)
console.log(`📚 Discovery: ${baseUrl}:${port}/.well-known/`)
console.log('')