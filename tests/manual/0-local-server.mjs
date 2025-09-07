import { RemoteServer } from 'flowmcpServers'
import { SchemaImporter } from 'schemaImporter'
import { FlowMCP } from 'flowmcp'
import { OAuthMiddleware } from '../../src/index.mjs'
import { TestUtils } from '../helpers/utils.mjs'

/**
 * Manual Test: OAuth-geschützter MCP Server
 * 
 * Dieser Test erstellt einen lokalen MCP Server mit OAuth-Middleware
 * zum Testen in der realen Umgebung.
 * 
 * Verwendung:
 * 1. Keycloak-Server starten
 * 2. Client in Keycloak konfigurieren  
 * 3. ../oauth-flowmcp.env-Datei konfigurieren
 * 4. node tests/manual/0-local-server.mjs
 * 5. Server läuft auf http://localhost:3000
 */

async function createTestServer() {
    TestUtils.log( 'Starte OAuth-geschützten MCP Test-Server...', 'info' )

    // OAuth-Konfiguration aus .env-Datei laden
    const { isValid, config: oauthConfig, message } = TestUtils.validateOAuthSetup()
    
    if( !isValid ) {
        TestUtils.log( `OAuth-Setup unvollständig: ${message}`, 'error' )
        TestUtils.log( 'Bitte ../oauth-flowmcp.env-Datei konfigurieren', 'warn' )
        TestUtils.log( 'Beispiel-Konfiguration wurde in ../oauth-flowmcp.env erstellt', 'info' )
        process.exit( 1 )
    }

    TestUtils.log( `Keycloak URL: ${oauthConfig.keycloakUrl}`, 'success' )
    TestUtils.log( `Realm: ${oauthConfig.realm}`, 'success' )
    TestUtils.log( `Client ID: ${oauthConfig.clientId}`, 'success' )

    // OAuth-Middleware erstellen mit neuer Multi-Realm API
    const middleware = await OAuthMiddleware.create( {
        realmsByRoute: {
            '/api': {
                keycloakUrl: oauthConfig.keycloakUrl,
                realm: oauthConfig.realm,
                clientId: oauthConfig.clientId,
                clientSecret: oauthConfig.clientSecret,
                requiredScopes: [ 'mcp:access' ],
                resourceUri: 'http://localhost:3000/api'
            }
        }
    } )

    TestUtils.log( 'Lade verfügbare Schemas...', 'info' )
    
    // Schemas laden mit korrekter SchemaImporter API
    let schemaList
    try {
        schemaList = await SchemaImporter.loadFromFolder({
            schemaRootFolder: './../schemas/v1.2.0/',
            excludeSchemasWithImports: true,
            excludeSchemasWithRequiredServerParams: true,
            addAdditionalMetaData: true,
            outputType: null // Vollständige Schema-Objekte
        })
        TestUtils.log( `${schemaList.length} Schemas geladen`, 'success' )
    } catch( error ) {
        TestUtils.log( 'Verwende Fallback-Schema da SchemaImporter fehlgeschlagen', 'warn' )
        TestUtils.log( `Error: ${error.message}`, 'warn' )
        
        // Fallback: FlowMCP-kompatibles Test-Schema
        schemaList = [{
            schema: {
                namespace: 'test-weather',
                name: 'Weather API Test',
                description: 'Simple weather API for OAuth testing',
                flowMCP: '1.2.0',
                root: 'https://api.test.com',
                requiredServerParams: [],
                routes: {
                    getCurrentWeather: {
                        method: 'GET',
                        path: '/weather/current',
                        description: 'Get current weather data',
                        parameters: {
                            city: { type: 'string', description: 'City name', required: true }
                        },
                        headers: {},
                        tests: [{
                            description: 'Test current weather for Berlin',
                            parameters: { city: 'Berlin' },
                            expectedStatus: 200
                        }]
                    }
                }
            },
            folderName: 'test-weather',
            absolutePath: '/test/weather.mjs',
            hasImport: false
        }]
    }

    // RemoteServer erstellen 
    const remoteServer = new RemoteServer({ silent: false })
    
    // Express-App für manuelle Endpunkte abrufen
    const app = remoteServer.getApp()
    
    // FlowMCP Activation Payloads vorbereiten
    let activationPayloads = []
    try {
        const arrayOfSchemas = schemaList.map( ( item ) => item.schema )
        const envObject = {} // Leer für Test-Schemas ohne Server-Parameter
        
        const result = FlowMCP.prepareActivations({ arrayOfSchemas, envObject })
        activationPayloads = result.activationPayloads
        TestUtils.log( `${activationPayloads.length} Activation Payloads erstellt`, 'success' )
    } catch( error ) {
        TestUtils.log( `FlowMCP Preparation fehlgeschlagen: ${error.message}`, 'error' )
        activationPayloads = [] // Fallback zu leerem Array
    }

    TestUtils.log( 'Konfiguriere OAuth-Middleware...', 'info' )

    // Öffentliche Endpunkte
    app.get( '/', ( req, res ) => {
        res.json({ 
            message: 'OAuth-geschützter MCP Test-Server',
            version: '0.1.0',
            endpoints: {
                public: [
                    '/',
                    '/health',
                    '/.well-known/oauth-authorization-server',
                    '/.well-known/oauth-protected-resource', 
                    '/.well-known/jwks.json',
                    '/auth/login',
                    '/auth/callback'
                ],
                protected: [
                    '/api/*',
                    '/admin/*'
                ]
            },
            oauth: {
                authorizationUrl: `${oauthConfig.keycloakUrl}/realms/${oauthConfig.realm}/protocol/openid-connect/auth`,
                tokenUrl: `${oauthConfig.keycloakUrl}/realms/${oauthConfig.realm}/protocol/openid-connect/token`
            }
        })
    })

    app.get( '/health', ( req, res ) => {
        res.json({ 
            status: 'healthy', 
            timestamp: new Date().toISOString(),
            oauth: 'enabled',
            schemas: schemaList.length
        })
    })


    // Geschützte API-Endpunkte mit OAuth-Middleware
    // OAuth-Middleware mit neuem Router API verwenden
    app.use( middleware.router() )

    // Test-API-Endpunkte
    app.get( '/api/weather', ( req, res ) => {
        TestUtils.log( `Weather API aufgerufen von: ${req.user.sub}`, 'info' )
        TestUtils.log( `Scopes: ${req.scopes.join(', ')}`, 'info' )
        
        res.json({
            temperature: 22.5,
            humidity: 65,
            condition: 'Partly cloudy',
            location: 'Test City',
            timestamp: new Date().toISOString(),
            user: req.user.sub,
            scopes: req.scopes,
            authenticationMethod: 'OAuth 2.1 + PKCE'
        })
    })

    app.get( '/api/profile', ( req, res ) => {
        TestUtils.log( `Profile API aufgerufen von: ${req.user.sub}`, 'info' )
        
        res.json({
            user: req.user,
            roles: req.roles,
            scopes: req.scopes,
            timestamp: new Date().toISOString(),
            tokenInfo: {
                issuer: req.user.iss,
                audience: req.user.aud,
                expiresAt: new Date( req.user.exp * 1000 ).toISOString()
            }
        })
    })

    // Admin-Endpunkt (erfordert admin-Rolle)
    app.get( '/api/admin', ( req, res ) => {
        TestUtils.log( `Admin API aufgerufen von: ${req.user.sub}`, 'info' )
        TestUtils.log( `Rollen: ${req.roles.join(', ')}`, 'info' )
        
        res.json({
            message: 'Admin-Bereich',
            schemas: schemaList.length,
            server: 'OAuth-geschützter MCP Server',
            user: req.user.sub,
            roles: req.roles,
            serverStats: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                node: process.version
            }
        })
    })

    // MCP Server mit FlowMCP-Integration als geschützter Endpunkt
    if( activationPayloads.length > 0 ) {
        TestUtils.log( 'Konfiguriere FlowMCP Server Route...', 'info' )
        
        // Routes Activation Payloads für RemoteServer vorbereiten
        const routesActivationPayloads = [{
            routePath: '/mcp',
            protocol: 'sse', // Server Sent Events für MCP
            bearerToken: null, // Wird durch OAuth-Middleware geschützt
            activationPayloads: activationPayloads.slice( 0, 3 ) // Nur erste 3 für Test
        }]
        
        // MCP Server starten (auf separatem Port oder als Route)
        try {
            // Hier würde normalerweise der MCP Server gestartet werden
            // Da wir aber OAuth-Integration testen, erstellen wir manuelle Schema-Endpunkte
            
            const testSchemas = activationPayloads.slice( 0, 3 )
            TestUtils.log( `Aktiviere ${testSchemas.length} FlowMCP Test-Tools`, 'info' )
            
            testSchemas.forEach( ( { schema }, index ) => {
                const schemaPath = `/api/mcp/schema/${schema.namespace}`
                const toolsPath = `/api/mcp/tools/${schema.namespace}`
                
                // Schema Info Endpoint
                app.get( schemaPath, ( req, res ) => {
                    TestUtils.log( `MCP Schema aufgerufen: ${schema.namespace}`, 'info' )
                    res.json({
                        namespace: schema.namespace,
                        name: schema.name || 'Unknown Schema',
                        description: schema.description || '',
                        routes: Object.keys( schema.routes || {} ),
                        toolsCount: Object.keys( schema.routes || {} ).length,
                        user: req.user.sub,
                        accessedAt: new Date().toISOString()
                    })
                })
                
                // Tools Endpoint für jede Route im Schema
                app.get( toolsPath, ( req, res ) => {
                    TestUtils.log( `MCP Tools aufgerufen: ${schema.namespace}`, 'info' )
                    const routes = schema.routes || {}
                    const tools = Object
                        .entries( routes )
                        .map( ( [ routeName, routeConfig ] ) => ({
                            name: `${schema.namespace}_${routeName}`,
                            description: routeConfig.description || `Tool for ${routeName}`,
                            method: routeConfig.method || 'GET',
                            path: routeConfig.path || `/${routeName}`,
                            parameters: routeConfig.parameters || {},
                            protected: true,
                            oauth: {
                                user: req.user.sub,
                                scopes: req.scopes
                            }
                        }) )
                    
                    res.json({
                        namespace: schema.namespace,
                        tools,
                        totalTools: tools.length,
                        accessedAt: new Date().toISOString()
                    })
                })
            })
        } catch( error ) {
            TestUtils.log( `MCP Server Konfiguration fehlgeschlagen: ${error.message}`, 'warn' )
        }
    }

    // Server starten
    const PORT = oauthConfig.testServerPort
    
    // Da wir den Express Server manuell verwenden, starten wir nur den HTTP Server
    app.listen( PORT, () => {
        console.log( '' )
        TestUtils.log( 'OAuth-geschützter MCP Server gestartet!', 'success' )
        console.log( '' )
        console.log( `📍 Server URL: http://localhost:${PORT}` )
        console.log( `🔐 Login URL: http://localhost:${PORT}/api/auth/login` )
        console.log( `📊 Health Check: http://localhost:${PORT}/health` )
        console.log( '' )
        console.log( '🔑 OAuth Endpoints:' )
        console.log( `   Authorization Server: http://localhost:${PORT}/.well-known/oauth-authorization-server` )
        console.log( `   Protected Resource: http://localhost:${PORT}/.well-known/oauth-protected-resource/api` )
        console.log( `   JWKS: http://localhost:${PORT}/.well-known/jwks.json` )
        console.log( '' )
        console.log( '🛡️  Geschützte APIs (benötigen Bearer Token):' )
        console.log( `   Weather API: http://localhost:${PORT}/api/weather` )
        console.log( `   Profile API: http://localhost:${PORT}/api/profile` )
        console.log( `   Admin API: http://localhost:${PORT}/api/admin` )
        
        if( activationPayloads.length > 0 ) {
            console.log( '' )
            console.log( '🔧 MCP FlowMCP APIs:' )
            activationPayloads.slice( 0, 3 ).forEach( ( { schema } ) => {
                console.log( `   Schema ${schema.namespace}: http://localhost:${PORT}/api/mcp/schema/${schema.namespace}` )
                console.log( `   Tools ${schema.namespace}: http://localhost:${PORT}/api/mcp/tools/${schema.namespace}` )
            })
        }
        console.log( '' )
        console.log( '🧪 Test-Workflow:' )
        console.log( '   1. Gehe zu /api/auth/login für OAuth-Flow' )
        console.log( '   2. Kopiere access_token aus der Antwort' )
        console.log( '   3. Verwende Token: curl -H "Authorization: Bearer TOKEN" http://localhost:' + PORT + '/api/weather' )
        console.log( '' )
    })

    return remoteServer
}

// Server starten wenn direkt ausgeführt
if( import.meta.url === `file://${process.argv[1]}` ) {
    createTestServer().catch( ( error ) => {
        TestUtils.log( `Server-Start fehlgeschlagen: ${error.message}`, 'error' )
        process.exit( 1 )
    })
}

export { createTestServer }