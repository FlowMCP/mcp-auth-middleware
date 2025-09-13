/**
 * Community Server Integration Tests
 * 
 * Tests the integration of the new multi-realm OAuth middleware with
 * FlowMCP Community Server to ensure backward compatibility and new features.
 */

import { McpAuthMiddleware } from '../../src/index.mjs'
import { TestUtils } from '../helpers/utils.mjs'

// Test configuration using .auth.env.example
const config = {
    envPath: '../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    silent: true
}

describe( 'Community Server Integration', () => {
    let middleware
    let testConfig
    
    beforeEach( async () => {
        // Use mock configuration for testing
        testConfig = {
            routes: {
                '/mcp': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid mcp:access',
                    audience: 'http://localhost:3000/mcp',
                    realm: 'test-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: [ 'openid', 'mcp:access' ],
                    requiredRoles: [ 'user' ]
                },
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'api-client',
                    clientSecret: 'api-secret',
                    scope: 'openid api:read api:write',
                    audience: 'http://localhost:3000/api',
                    realm: 'api-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: [ 'openid', 'api:read', 'api:write' ],
                    requiredRoles: [ 'user' ]
                }
            },
            silent: true
        }
        
        middleware = await McpAuthMiddleware.create({ 
            routes: testConfig.routes, 
            silent: testConfig.silent 
        })
    } )
    
    describe( 'FlowMCP RemoteServer Integration', () => {
        test( 'middleware provides Express router for RemoteServer middleware array', () => {
            const router = middleware.router()
            
            // Should be an Express router that can be used as middleware
            expect( router ).toBeDefined()
            expect( typeof router ).toBe( 'function' )
            expect( router.stack ).toBeDefined() // Express router has stack property
        } )
        
        test( 'router contains all required OAuth endpoints', () => {
            const router = middleware.router()
            const routes = []
            
            // Extract routes from router stack recursively
            const extractRoutes = ( layer, basePath = '' ) => {
                if( layer.route ) {
                    // Direct route
                    routes.push( {
                        method: Object.keys( layer.route.methods )[0].toUpperCase(),
                        path: basePath + layer.route.path
                    } )
                } else if( layer.name === 'router' && layer.handle && layer.handle.stack ) {
                    // Nested router
                    const routerPath = layer.regexp.source.includes( '^' ) ? 
                        layer.regexp.source.match( /\^(.*?)\?\$/ )?.[1]?.replace( /\\\//g, '/' ) || '' :
                        ''
                    
                    layer.handle.stack.forEach( nestedLayer => {
                        extractRoutes( nestedLayer, basePath + routerPath )
                    } )
                }
            }
            
            router.stack.forEach( layer => extractRoutes( layer ) )
            
            // Should contain key OAuth endpoints (subset that are always present)
            const requiredEndpoints = [
                '/.well-known/oauth-authorization-server',
                '/.well-known/jwks.json',
                '/mcp/auth/login',
                '/api/auth/login'
            ]
            
            requiredEndpoints.forEach( path => {
                const hasEndpoint = routes.some( route => 
                    route.path === path || route.path.endsWith( path )
                )
                expect( hasEndpoint ).toBe( true )
            } )
            
            // Verify we have at least the expected number of routes
            expect( routes.length ).toBeGreaterThanOrEqual( 6 )
        } )
        
        test( 'middleware configuration is compatible with RemoteServer.create()', async () => {
            // Mock the RemoteServer.create interface
            const mockRemoteServerConfig = {
                middleware: middleware.router(),
                transport: 'sse',
                port: 3002
            }
            
            // Should accept the router as middleware without errors
            expect( mockRemoteServerConfig.middleware ).toBeDefined()
            expect( typeof mockRemoteServerConfig.middleware ).toBe( 'function' )
            
            // Test that configuration follows expected pattern
            expect( mockRemoteServerConfig.transport ).toBe( 'sse' )
            expect( typeof mockRemoteServerConfig.port ).toBe( 'number' )
        } )
    } )
    
    describe( 'Multi-Realm Route Protection', () => {
        test( 'different routes can use different realms', () => {
            const mcpConfig = middleware.getRouteConfig( { routePath: '/mcp' } )
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )
            
            expect( mcpConfig ).toBeDefined()
            expect( apiConfig ).toBeDefined()
            
            // Should have different realm configurations
            expect( mcpConfig.realm ).toBe( 'test-realm' )
            expect( apiConfig.realm ).toBe( 'api-realm' )

            // Should have different scope requirements (OIDC standard scopes filtered out)
            expect( mcpConfig.requiredScopes ).toEqual( ['mcp:access'] )
            expect( apiConfig.requiredScopes ).toEqual( ['api:read', 'api:write'] )
        } )
        
        test( 'route mapping is correctly configured', () => {
            const routes = middleware.getRoutes()

            expect( routes ).toEqual( ['/mcp', '/api'] )

            const mcpConfig = middleware.getRouteConfig( { routePath: '/mcp' } )
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )

            expect( mcpConfig.authType ).toBe( 'oauth21_auth0' )
            expect( apiConfig.authType ).toBe( 'oauth21_auth0' )
            expect( mcpConfig.audience ).toBe( 'http://localhost:3000/mcp' )
            expect( apiConfig.audience ).toBe( 'http://localhost:3000/api' )
        } )
    } )
    
    describe( 'Backward Compatibility', () => {
        test( 'middleware maintains FlowMCP compatibility patterns', async () => {
            // Test that the new API maintains compatibility with expected usage patterns
            
            // 1. Should create middleware with async pattern
            const compatibilityMiddleware = await McpAuthMiddleware.create({
                routes: {
                    '/': { // Root route for maximum compatibility
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'mcp-client',
                        clientSecret: 'mcp-secret',
                        scope: 'openid mcp:access',
                        audience: 'http://localhost:3000/',
                        realm: 'root-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: [ 'openid', 'mcp:access' ],
                        requiredRoles: [ 'user' ]
                    }
                },
                silent: true
            })
            
            expect( compatibilityMiddleware ).toBeDefined()
            expect( typeof compatibilityMiddleware.router ).toBe( 'function' )
            
            // 2. Should provide single router method (not multiple methods)
            const router = compatibilityMiddleware.router()
            expect( typeof router ).toBe( 'function' )
            
            // 3. Legacy methods should not exist
            expect( compatibilityMiddleware.mcp ).toBeUndefined()
            expect( compatibilityMiddleware.mcpWithRBAC ).toBeUndefined()
            expect( compatibilityMiddleware.wellKnownAuthorizationServer ).toBeUndefined()
            expect( compatibilityMiddleware.wellKnownJwks ).toBeUndefined()
        } )
        
        test( 'root route configuration works for legacy compatibility', async () => {
            const rootMiddleware = await McpAuthMiddleware.create({
                routes: {
                    '/': {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'legacy-client',
                        clientSecret: 'legacy-secret',
                        scope: 'openid legacy:access',
                        audience: 'http://localhost:3000/',
                        realm: 'legacy-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: [ 'openid', 'legacy:access' ],
                        requiredRoles: [ 'user' ]
                    }
                },
                silent: true
            })
            
            const routes = rootMiddleware.getRoutes()
            expect( routes ).toContain( '/' )
            
            const rootConfig = rootMiddleware.getRouteConfig( { routePath: '/' } )
            expect( rootConfig.realm ).toBe( 'legacy-realm' )
        } )
    } )
    
    describe( 'Discovery Endpoints Integration', () => {
        test( 'OAuth Authorization Server metadata includes all routes', () => {
            const routes = middleware.getRoutes()

            // Should have both routes configured
            expect( routes ).toHaveLength( 2 )

            const mcpConfig = middleware.getRouteConfig( { routePath: '/mcp' } )
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )

            expect( mcpConfig.providerUrl ).toBe( 'https://your-first-auth0-domain.auth0.com' )
            expect( apiConfig.providerUrl ).toBe( 'https://your-first-auth0-domain.auth0.com' )

            // Each route should have its own audience URI
            expect( mcpConfig.audience ).toBe( 'http://localhost:3000/mcp' )
            expect( apiConfig.audience ).toBe( 'http://localhost:3000/api' )
        } )
        
        test( 'Protected Resource metadata is route-specific', () => {
            const mcpConfig = middleware.getRouteConfig( { routePath: '/mcp' } )
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )
            
            // Each route should have its own resource metadata
            expect( mcpConfig.resourceUri ).toBe( 'http://localhost:3000/mcp' )
            expect( apiConfig.resourceUri ).toBe( 'http://localhost:3000/api' )
            
            // Scopes should be route-specific (OIDC standard scopes filtered out)
            expect( mcpConfig.requiredScopes ).toEqual( ['mcp:access'] )
            expect( apiConfig.requiredScopes ).toEqual( ['api:read', 'api:write'] )
        } )
    } )
    
    describe( 'Error Handling Integration', () => {
        test( 'invalid route configuration fails gracefully', async () => {
            await expect( async () => {
                await McpAuthMiddleware.create({
                    routes: {
                        '/invalid': {
                            // Missing required fields
                        }
                    },
                    silent: true
                })
            } ).rejects.toThrow()
        } )
        
        test( 'missing route configuration returns undefined', () => {
            const nonExistentConfig = middleware.getRouteConfig( { routePath: '/nonexistent' } )
            expect( nonExistentConfig ).toBeUndefined()
        } )
    } )
    
    describe( 'Performance Integration', () => {
        test( 'middleware creation completes within reasonable time', async () => {
            const startTime = Date.now()
            
            const perfMiddleware = await McpAuthMiddleware.create({
                routes: {
                    '/perf1': {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'perf-client-1',
                        clientSecret: 'perf-secret-1',
                        scope: 'openid perf:test',
                        audience: 'http://localhost:3000/perf1',
                        realm: 'perf-realm-1',
                        authFlow: 'authorization_code',
                        requiredScopes: [ 'openid', 'perf:test' ],
                        requiredRoles: [ 'user' ]
                    },
                    '/perf2': {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'perf-client-2',
                        clientSecret: 'perf-secret-2',
                        scope: 'openid perf:test',
                        audience: 'http://localhost:3000/perf2',
                        realm: 'perf-realm-2',
                        authFlow: 'authorization_code',
                        requiredScopes: [ 'openid', 'perf:test' ],
                        requiredRoles: [ 'user' ]
                    }
                },
                silent: true
            })
            
            const creationTime = Date.now() - startTime
            
            expect( perfMiddleware ).toBeDefined()
            expect( creationTime ).toBeLessThan( 5000 ) // Should create within 5 seconds
        } )
        
        test( 'router method execution is fast', () => {
            const iterations = 1000
            const startTime = Date.now()
            
            for( let i = 0; i < iterations; i++ ) {
                const router = middleware.router()
                expect( router ).toBeDefined()
            }
            
            const totalTime = Date.now() - startTime
            const avgTime = totalTime / iterations
            
            expect( avgTime ).toBeLessThan( 1 ) // Should average less than 1ms per call
        } )
    } )
} )