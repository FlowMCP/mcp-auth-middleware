#!/usr/bin/env node

/**
 * Production OAuth Middleware Server
 * 
 * Direct Node.js production server with HTTPS, security headers,
 * and multi-realm OAuth support.
 */

import express from 'express'
import { OAuthMiddleware } from '../index.mjs'
import { readFileSync, existsSync } from 'fs'
import https from 'https'
import http from 'http'

const createProductionApp = async () => {
    const app = express()
    
    // Security middleware
    app.use((req, res, next) => {
        // Security headers
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('X-Frame-Options', 'DENY')
        res.setHeader('X-XSS-Protection', '1; mode=block')
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
        
        // Remove server information
        res.removeHeader('X-Powered-By')
        
        next()
    })
    
    // Parse JSON and form data with size limits
    app.use(express.json({ limit: '10mb' }))
    app.use(express.urlencoded({ extended: true, limit: '10mb' }))
    
    // Build realm configuration from environment variables
    const realmsByRoute = {}
    const envKeys = Object.keys(process.env)
    
    // Detect realm configurations from environment
    const realmPrefixes = new Set()
    envKeys.forEach(key => {
        if (key.endsWith('_REALM')) {
            const prefix = key.replace('_REALM', '')
            realmPrefixes.add(prefix)
        }
    })
    
    // Build realm configurations
    for (const prefix of realmPrefixes) {
        const realm = process.env[`${prefix}_REALM`]
        const clientId = process.env[`${prefix}_CLIENT_ID`]
        const clientSecret = process.env[`${prefix}_CLIENT_SECRET`]
        const requiredScopes = process.env[`${prefix}_REQUIRED_SCOPES`]
        const resourceUri = process.env[`${prefix}_RESOURCE_URI`]
        
        if (realm && clientId && clientSecret && requiredScopes && resourceUri) {
            const routePath = `/${prefix.toLowerCase().replace('_', '-')}`
            
            realmsByRoute[routePath] = {
                keycloakUrl: process.env.KEYCLOAK_URL,
                realm,
                clientId,
                clientSecret,
                requiredScopes: requiredScopes.split(',').map(s => s.trim()),
                resourceUri
            }
            
            console.log(`✅ Configured realm: ${routePath} → ${realm}`)
        }
    }
    
    if (Object.keys(realmsByRoute).length === 0) {
        console.error('❌ No realm configurations found in environment variables')
        console.error('   Please configure at least one realm with: PREFIX_REALM, PREFIX_CLIENT_ID, etc.')
        process.exit(1)
    }
    
    // Create OAuth middleware
    console.log('🔐 Initializing OAuth middleware...')
    const middleware = await OAuthMiddleware.create({
        realmsByRoute,
        silent: process.env.NODE_ENV === 'production'
    })
    
    console.log(`✅ OAuth middleware initialized for routes: ${middleware.getRoutes().join(', ')}`)
    
    // Add OAuth middleware
    app.use(middleware.router())
    
    // Health check endpoint
    app.get('/health', (req, res) => {
        const uptime = process.uptime()
        const memoryUsage = process.memoryUsage()
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: Math.floor(uptime),
            memory: {
                used: Math.round(memoryUsage.heapUsed / 1024 / 1024),
                total: Math.round(memoryUsage.heapTotal / 1024 / 1024)
            },
            oauth: {
                routes: middleware.getRoutes(),
                realms: middleware.getRealms().map(r => ({
                    route: r.route,
                    realm: r.realm
                }))
            }
        })
    })
    
    // Root endpoint
    app.get('/', (req, res) => {
        res.json({
            service: 'Multi-Realm OAuth 2.1 Middleware',
            version: '2.0.0',
            architecture: 'multi-realm',
            rfc_compliance: ['8414', '9728', '8707'],
            oauth_version: '2.1',
            routes: middleware.getRoutes(),
            endpoints: {
                discovery: '/.well-known/oauth-authorization-server',
                jwks: '/.well-known/jwks.json',
                health: '/health'
            }
        })
    })
    
    return app
}

const startServer = async () => {
    try {
        const app = await createProductionApp()
        const port = process.env.PORT || 3000
        
        // Check if SSL certificates are configured
        const sslCertPath = process.env.SSL_CERT_PATH
        const sslKeyPath = process.env.SSL_KEY_PATH
        
        if (process.env.NODE_ENV === 'production' && sslCertPath && sslKeyPath) {
            // Production HTTPS server
            if (!existsSync(sslCertPath) || !existsSync(sslKeyPath)) {
                console.error('❌ SSL certificates not found:', { sslCertPath, sslKeyPath })
                process.exit(1)
            }
            
            const httpsOptions = {
                cert: readFileSync(sslCertPath),
                key: readFileSync(sslKeyPath)
            }
            
            const server = https.createServer(httpsOptions, app)
            
            server.listen(port, () => {
                console.log('🚀 OAuth Middleware Production Server Started')
                console.log(`   HTTPS: https://localhost:${port}`)
                console.log(`   Process: ${process.pid}`)
                console.log(`   Environment: ${process.env.NODE_ENV}`)
                console.log('   Security: HTTPS ✅, OAuth 2.1 ✅, RFC Compliant ✅')
            })
            
            return server
        } else {
            // Development or HTTP server
            if (process.env.NODE_ENV === 'production') {
                console.warn('⚠️  Running production without SSL certificates')
                console.warn('   Set SSL_CERT_PATH and SSL_KEY_PATH for HTTPS')
            }
            
            const server = http.createServer(app)
            
            server.listen(port, () => {
                console.log('🚀 OAuth Middleware Server Started')
                console.log(`   HTTP: http://localhost:${port}`)
                console.log(`   Process: ${process.pid}`)
                console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`)
                console.log(`   SSL: ${process.env.NODE_ENV === 'production' ? '⚠️  Disabled' : '🔓 Development'}`)
            })
            
            return server
        }
    } catch (error) {
        console.error('❌ Server startup failed:', error.message)
        console.error('')
        console.error('🔧 Troubleshooting:')
        console.error('   1. Check environment variables (KEYCLOAK_URL, *_REALM, etc.)')
        console.error('   2. Verify Keycloak connectivity')
        console.error('   3. Ensure SSL certificates exist (production)')
        console.error('   4. Check port availability')
        console.error('')
        process.exit(1)
    }
}

// Graceful shutdown handler
const gracefulShutdown = (server) => {
    const shutdown = (signal) => {
        console.log(`\\n🛑 Received ${signal}, shutting down gracefully...`)
        
        server.close((error) => {
            if (error) {
                console.error('❌ Error during server shutdown:', error.message)
                process.exit(1)
            } else {
                console.log('✅ Server closed successfully')
                process.exit(0)
            }
        })
        
        // Force shutdown after 10 seconds
        setTimeout(() => {
            console.error('❌ Forced shutdown after timeout')
            process.exit(1)
        }, 10000)
    }
    
    process.on('SIGTERM', () => shutdown('SIGTERM'))
    process.on('SIGINT', () => shutdown('SIGINT'))
}

// Start the server
if (import.meta.url === `file://${process.argv[1]}`) {
    const server = await startServer()
    gracefulShutdown(server)
}