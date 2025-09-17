import express from 'express'
import request from 'supertest'
import { McpAuthMiddleware } from '../../src/index.mjs'

describe('StaticBearer Integration Tests', () => {
    let app, middleware

    const testConfig = {
        staticBearer: {
            tokenSecret: 'integration-test-token-123456',
            attachedRoutes: [ '/api' ]
        },
        silent: true,
        baseUrl: 'http://localhost:3000'
    }

    beforeEach(async () => {
        middleware = await McpAuthMiddleware.create(testConfig)

        app = express()
        app.use(express.json())
        app.use(middleware.router())

        // Add a protected test endpoint
        app.get('/api/protected', (req, res) => {
            res.json({
                message: 'Protected resource accessed',
                user: req.user,
                authType: req.authType
            })
        })
    })

    describe('StaticBearer Authentication Flow', () => {
        test('allows access with correct Bearer token', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer integration-test-token-123456')
                .expect(200)

            expect(response.body.message).toBe('Protected resource accessed')
            expect(response.body.user).toBeDefined()
            expect(response.body.authType).toBe('staticBearer')
        })

        test('allows access with correct bearer token (lowercase)', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'bearer integration-test-token-123456')
                .expect(200)

            expect(response.body.message).toBe('Protected resource accessed')
        })

        test('allows access with extra spaces in header', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer   integration-test-token-123456   ')
                .expect(200)

            expect(response.body.message).toBe('Protected resource accessed')
        })

        test('blocks access with incorrect token', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer wrong-token')
                .expect(401)

            expect(response.body.error).toBe('Unauthorized')
            expect(response.body.message).toBe('Invalid bearer token')
        })

        test('blocks access without Authorization header', async () => {
            const response = await request(app)
                .get('/api/protected')
                .expect(401)

            expect(response.body.error).toBe('Unauthorized')
            expect(response.body.message).toBe('Authorization header required')
        })

        test('blocks access with malformed Authorization header', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Basic dGVzdDp0ZXN0')
                .expect(401)

            expect(response.body.error).toBe('Unauthorized')
            expect(response.body.message).toBe('Bearer token required')
        })

        test('blocks access with empty Bearer token', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer')
                .expect(401)

            expect(response.body.error).toBe('Unauthorized')
            expect(response.body.message).toBe('Bearer token required')
        })

        test('blocks access with only spaces after Bearer', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer   ')
                .expect(401)

            expect(response.body.error).toBe('Unauthorized')
            expect(response.body.message).toBe('Bearer token required')
        })
    })

    describe('Multiple Route Support', () => {
        let multiRouteApp, multiRouteMiddleware

        beforeEach(async () => {
            const multiRouteConfig = {
                staticBearer: {
                    tokenSecret: 'api-token-123456',
                    attachedRoutes: [ '/api', '/admin' ]
                },
                silent: true,
        baseUrl: 'http://localhost:3000'
            }

            multiRouteMiddleware = await McpAuthMiddleware.create(multiRouteConfig)

            multiRouteApp = express()
            multiRouteApp.use(express.json())
            multiRouteApp.use(multiRouteMiddleware.router())

            multiRouteApp.get('/api/data', (req, res) => {
                res.json({ endpoint: 'api', message: 'API data' })
            })

            multiRouteApp.get('/admin/users', (req, res) => {
                res.json({ endpoint: 'admin', message: 'Admin users' })
            })
        })

        test('allows API access with correct token', async () => {
            const response = await request(multiRouteApp)
                .get('/api/data')
                .set('Authorization', 'Bearer api-token-123456')
                .expect(200)

            expect(response.body.endpoint).toBe('api')
        })

        test('allows admin access with correct token', async () => {
            const response = await request(multiRouteApp)
                .get('/admin/users')
                .set('Authorization', 'Bearer api-token-123456')
                .expect(200)

            expect(response.body.endpoint).toBe('admin')
        })

        test('blocks API access with wrong token', async () => {
            await request(multiRouteApp)
                .get('/api/data')
                .set('Authorization', 'Bearer wrong-token')
                .expect(401)
        })

        test('blocks admin access with wrong token', async () => {
            await request(multiRouteApp)
                .get('/admin/users')
                .set('Authorization', 'Bearer wrong-token')
                .expect(401)
        })
    })

    describe('Mixed Auth Types Support', () => {
        let mixedApp, mixedMiddleware

        beforeEach(async () => {
            const mixedConfig = {
                staticBearer: {
                    tokenSecret: 'static-bearer-token-123',
                    attachedRoutes: [ '/api' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                },
                silent: true,
        baseUrl: 'http://localhost:3000'
            }

            mixedMiddleware = await McpAuthMiddleware.create(mixedConfig)

            mixedApp = express()
            mixedApp.use(express.json())
            mixedApp.use(mixedMiddleware.router())

            mixedApp.get('/api/simple', (req, res) => {
                res.json({ authType: 'staticBearer', message: 'Simple auth' })
            })
        })

        test('creates middleware with mixed auth types', () => {
            expect(mixedMiddleware).toBeDefined()
        })

        test('handles staticBearer route correctly', async () => {
            const response = await request(mixedApp)
                .get('/api/simple')
                .set('Authorization', 'Bearer static-bearer-token-123')
                .expect(200)

            expect(response.body.authType).toBe('staticBearer')
        })

        test('getRoutes includes both auth types', () => {
            const routes = mixedMiddleware.getRoutes()
            expect(routes).toHaveLength(2)
            expect(routes).toContain('/api')
            expect(routes).toContain('/oauth')
        })

        test('getRouteConfig returns correct config for staticBearer', () => {
            const apiConfig = mixedMiddleware.getRouteConfig({ routePath: '/api' })
            expect(apiConfig.authType).toBe('staticBearer')
            expect(apiConfig.tokenSecret).toBe('static-bearer-token-123')
        })

        test('getRouteConfig returns correct config for oauth21_scalekit', () => {
            const oauthConfig = mixedMiddleware.getRouteConfig({ routePath: '/oauth' })
            expect(oauthConfig.authType).toBe('oauth21_scalekit')
            expect(oauthConfig.providerUrl).toBe('https://auth.scalekit.com')
        })
    })

    describe('Edge Cases', () => {
        test('handles very long tokens', async () => {
            const longToken = 'a'.repeat(1000)
            const longTokenConfig = {
                staticBearer: {
                    tokenSecret: longToken,
                    attachedRoutes: [ '/api' ]
                },
                silent: true,
        baseUrl: 'http://localhost:3000'
            }

            const longTokenMiddleware = await McpAuthMiddleware.create(longTokenConfig)
            const longTokenApp = express()
            longTokenApp.use(longTokenMiddleware.router())
            longTokenApp.get('/api/test', (req, res) => res.json({ ok: true }))

            const response = await request(longTokenApp)
                .get('/api/test')
                .set('Authorization', `Bearer ${longToken}`)
                .expect(200)

            expect(response.body.ok).toBe(true)
        })

        test('handles tokens with special characters', async () => {
            const specialToken = 'token-with_special.chars+and=symbols&more%20stuff'
            const specialConfig = {
                staticBearer: {
                    tokenSecret: specialToken,
                    attachedRoutes: [ '/api' ]
                },
                silent: true,
        baseUrl: 'http://localhost:3000'
            }

            const specialMiddleware = await McpAuthMiddleware.create(specialConfig)
            const specialApp = express()
            specialApp.use(specialMiddleware.router())
            specialApp.get('/api/test', (req, res) => res.json({ ok: true }))

            const response = await request(specialApp)
                .get('/api/test')
                .set('Authorization', `Bearer ${specialToken}`)
                .expect(200)

            expect(response.body.ok).toBe(true)
        })
    })
})