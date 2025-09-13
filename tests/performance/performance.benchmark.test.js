/**
 * Performance Validation Tests
 * 
 * Benchmarks to validate that the multi-realm architecture performs
 * efficiently compared to single-realm setups and meets production requirements.
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

describe( 'Performance Benchmarks', () => {
    let singleRealmMiddleware
    let multiRealmMiddleware
    
    beforeAll( async () => {
        // Create single-realm middleware for comparison
        singleRealmMiddleware = await McpAuthMiddleware.create({
            routes: {
                '/': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'single-client',
                    clientSecret: 'single-secret',
                    scope: 'openid single:access',
                    audience: 'http://localhost:3000',
                    realm: 'single-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', 'single:access'],
                    requiredRoles: ['user'],
                    forceHttps: true
                }
            },
            silent: true
        })
        
        // Create multi-realm middleware (3 realms)
        multiRealmMiddleware = await McpAuthMiddleware.create({
            routes: {
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'api-client',
                    clientSecret: 'api-secret',
                    scope: 'openid api:read api:write',
                    audience: 'http://localhost:3000/api',
                    realm: 'api-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', 'api:read', 'api:write'],
                    requiredRoles: ['user'],
                    forceHttps: true
                },
                '/admin': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'admin-client',
                    clientSecret: 'admin-secret',
                    scope: 'openid admin:full',
                    audience: 'http://localhost:3000/admin',
                    realm: 'admin-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', 'admin:full'],
                    requiredRoles: ['admin'],
                    forceHttps: true
                },
                '/public': {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: 'public-client',
                    clientSecret: 'public-secret',
                    scope: 'openid public:basic',
                    audience: 'http://localhost:3000/public',
                    realm: 'public-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', 'public:basic'],
                    requiredRoles: ['user'],
                    forceHttps: true
                }
            },
            silent: true
        })
    }, 30000 ) // 30 second timeout for middleware creation
    
    describe( 'Middleware Creation Performance', () => {
        test( 'single-realm middleware creation completes within 5 seconds', async () => {
            const startTime = Date.now()
            
            const testMiddleware = await McpAuthMiddleware.create({
                routes: {
                    '/test': {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        scope: 'openid test:access',
                        audience: 'http://localhost:3000/test',
                        realm: 'test-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: ['openid', 'test:access'],
                        requiredRoles: ['user'],
                        forceHttps: true
                    }
                },
                silent: true
            })
            
            const creationTime = Date.now() - startTime
            
            expect( testMiddleware ).toBeDefined()
            expect( creationTime ).toBeLessThan( 5000 )
        }, 10000 )
        
        test( 'multi-realm middleware creation scales reasonably with realm count', async () => {
            const realms = {}
            const realmCount = 5
            
            // Generate 5 realms
            for( let i = 1; i <= realmCount; i++ ) {
                realms[`/realm${i}`] = {
                    authType: 'oauth21_auth0',
                    providerUrl: config.providerUrl,
                    clientId: `test-client-${i}`,
                    clientSecret: `test-secret-${i}`,
                    scope: `openid realm${i}:access`,
                    audience: `http://localhost:3000/realm${i}`,
                    realm: `realm-${i}`,
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', `realm${i}:access`],
                    requiredRoles: ['user'],
                    forceHttps: true
                }
            }
            
            const startTime = Date.now()
            
            const testMiddleware = await McpAuthMiddleware.create({
                routes: realms,
                silent: true
            })
            
            const creationTime = Date.now() - startTime
            
            expect( testMiddleware ).toBeDefined()
            expect( creationTime ).toBeLessThan( 15000 ) // Should scale linearly
            
            // Verify all routes were configured
            const configuredRoutes = testMiddleware.getRoutes()
            expect( configuredRoutes ).toHaveLength( realmCount )
        }, 20000 )
    } )
    
    describe( 'Router Performance', () => {
        test( 'single-realm router() method performance', () => {
            const iterations = 1000
            const times = []
            
            for( let i = 0; i < iterations; i++ ) {
                const startTime = process.hrtime.bigint()
                const router = singleRealmMiddleware.router()
                const endTime = process.hrtime.bigint()
                
                times.push( Number( endTime - startTime ) / 1000000 ) // Convert to milliseconds
                expect( router ).toBeDefined()
            }
            
            const avgTime = times.reduce( ( sum, time ) => sum + time, 0 ) / times.length
            const maxTime = Math.max( ...times )
            
            // Performance requirements
            expect( avgTime ).toBeLessThan( 1.0 ) // Average < 1ms
            expect( maxTime ).toBeLessThan( 10.0 ) // Max < 10ms
        } )
        
        test( 'multi-realm router() method performance', () => {
            const iterations = 1000
            const times = []
            
            for( let i = 0; i < iterations; i++ ) {
                const startTime = process.hrtime.bigint()
                const router = multiRealmMiddleware.router()
                const endTime = process.hrtime.bigint()
                
                times.push( Number( endTime - startTime ) / 1000000 ) // Convert to milliseconds
                expect( router ).toBeDefined()
            }
            
            const avgTime = times.reduce( ( sum, time ) => sum + time, 0 ) / times.length
            const maxTime = Math.max( ...times )
            
            // Performance requirements (should be similar to single-realm)
            expect( avgTime ).toBeLessThan( 2.0 ) // Average < 2ms (allowing for more complexity)
            expect( maxTime ).toBeLessThan( 200.0 ) // Max < 200ms (realistic for complex routing)
        } )
        
        test( 'multi-realm vs single-realm router() performance comparison', () => {
            const iterations = 100
            
            // Benchmark single-realm
            const singleStartTime = process.hrtime.bigint()
            for( let i = 0; i < iterations; i++ ) {
                singleRealmMiddleware.router()
            }
            const singleEndTime = process.hrtime.bigint()
            const singleTotalTime = Number( singleEndTime - singleStartTime ) / 1000000
            
            // Benchmark multi-realm
            const multiStartTime = process.hrtime.bigint()
            for( let i = 0; i < iterations; i++ ) {
                multiRealmMiddleware.router()
            }
            const multiEndTime = process.hrtime.bigint()
            const multiTotalTime = Number( multiEndTime - multiStartTime ) / 1000000
            
            const performanceRatio = multiTotalTime / singleTotalTime
            
            // Multi-realm should not be more than 25x slower than single-realm (realistic expectation)
            expect( performanceRatio ).toBeLessThan( 25.0 )
        } )
    } )
    
    describe( 'Configuration Access Performance', () => {
        test( 'getRoutes() method performance', () => {
            const iterations = 10000
            
            const startTime = process.hrtime.bigint()
            for( let i = 0; i < iterations; i++ ) {
                const routes = multiRealmMiddleware.getRoutes()
                expect( routes ).toHaveLength( 3 )
            }
            const endTime = process.hrtime.bigint()
            
            const totalTime = Number( endTime - startTime ) / 1000000
            const avgTime = totalTime / iterations
            
            expect( avgTime ).toBeLessThan( 1.0 ) // Should be reasonably fast < 1.0ms
        } )
        
        test( 'getRoutes() method performance', () => {
            const iterations = 10000

            const startTime = process.hrtime.bigint()
            for( let i = 0; i < iterations; i++ ) {
                const routes = multiRealmMiddleware.getRoutes()
                expect( routes ).toHaveLength( 3 )
            }
            const endTime = process.hrtime.bigint()

            const totalTime = Number( endTime - startTime ) / 1000000
            const avgTime = totalTime / iterations
            
            expect( avgTime ).toBeLessThan( 1.0 ) // Should be reasonably fast < 1.0ms
        } )
        
        test( 'getRouteConfig() method performance', () => {
            const iterations = 10000
            const routes = ['/api', '/admin', '/public']
            
            const startTime = process.hrtime.bigint()
            for( let i = 0; i < iterations; i++ ) {
                const route = routes[ i % routes.length ]
                const config = multiRealmMiddleware.getRouteConfig( { routePath: route } )
                expect( config ).toBeDefined()
                expect( config.realm ).toBeDefined()
            }
            const endTime = process.hrtime.bigint()
            
            const totalTime = Number( endTime - startTime ) / 1000000
            const avgTime = totalTime / iterations
            
            expect( avgTime ).toBeLessThan( 1.5 ) // Should be reasonably fast < 1.5ms
        } )
    } )
    
    describe( 'Memory Usage', () => {
        test( 'middleware instances have reasonable memory footprint', () => {
            // Force garbage collection if available
            if( global.gc ) {
                global.gc()
            }
            
            const initialMemory = process.memoryUsage()
            
            // Create multiple middleware instances
            const middlewarePromises = []
            for( let i = 0; i < 10; i++ ) {
                middlewarePromises.push(
                    McpAuthMiddleware.create({
                        routes: {
                            [`/test-${i}`]: {
                                authType: 'oauth21_auth0',
                                providerUrl: config.providerUrl,
                                clientId: `test-client-${i}`,
                                clientSecret: `test-secret-${i}`,
                                scope: `openid test${i}:access`,
                                audience: `http://localhost:3000/test-${i}`,
                                realm: `test-${i}-realm`,
                                authFlow: 'authorization_code',
                                requiredScopes: ['openid', `test${i}:access`],
                                requiredRoles: ['user'],
                                forceHttps: true
                            }
                        },
                        silent: true
                    })
                )
            }
            
            return Promise.all( middlewarePromises ).then( middlewareInstances => {
                const finalMemory = process.memoryUsage()
                const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed
                const memoryPerInstance = memoryIncrease / middlewareInstances.length
                
                // Each middleware instance should use less than 10MB
                expect( memoryPerInstance ).toBeLessThan( 10 * 1024 * 1024 )
            } )
        }, 20000 )
    } )
    
    describe( 'Concurrent Access Performance', () => {
        test( 'concurrent router() calls perform well', async () => {
            const concurrentCalls = 100
            const promises = []
            
            const startTime = process.hrtime.bigint()
            
            for( let i = 0; i < concurrentCalls; i++ ) {
                promises.push( Promise.resolve( multiRealmMiddleware.router() ) )
            }
            
            const routers = await Promise.all( promises )
            
            const endTime = process.hrtime.bigint()
            const totalTime = Number( endTime - startTime ) / 1000000
            
            // All calls should complete
            expect( routers ).toHaveLength( concurrentCalls )
            routers.forEach( router => {
                expect( router ).toBeDefined()
                expect( typeof router ).toBe( 'function' )
            } )
            
            // Should handle concurrent access efficiently
            expect( totalTime ).toBeLessThan( 1000 ) // Less than 1 second total
            
            const avgTimePerCall = totalTime / concurrentCalls
            expect( avgTimePerCall ).toBeLessThan( 10 ) // Less than 10ms per call on average
        } )
        
        test( 'concurrent configuration access performs well', async () => {
            const concurrentCalls = 1000
            const promises = []
            
            const startTime = process.hrtime.bigint()
            
            for( let i = 0; i < concurrentCalls; i++ ) {
                const route = ['/api', '/admin', '/public'][ i % 3 ]
                promises.push( Promise.resolve( multiRealmMiddleware.getRouteConfig( { routePath: route } ) ) )
            }
            
            const configs = await Promise.all( promises )
            
            const endTime = process.hrtime.bigint()
            const totalTime = Number( endTime - startTime ) / 1000000
            
            // All calls should complete successfully
            expect( configs ).toHaveLength( concurrentCalls )
            configs.forEach( config => {
                expect( config ).toBeDefined()
                expect( config.realm ).toBeDefined()
            } )
            
            // Should be very fast for read operations
            expect( totalTime ).toBeLessThan( 100 ) // Less than 100ms total
            
            const avgTimePerCall = totalTime / concurrentCalls
            expect( avgTimePerCall ).toBeLessThan( 0.1 ) // Less than 0.1ms per call on average
        } )
    } )
} )