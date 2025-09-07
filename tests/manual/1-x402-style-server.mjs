import { RemoteServer } from 'flowmcpServers'
import { SchemaImporter } from 'schemaImporter'
import { FlowMCP } from 'flowmcp'
import { OAuthMiddleware } from '../../src/index.mjs'
import { TestUtils } from '../helpers/utils.mjs'

/**
 * X402-Style OAuth-geschützter MCP Server
 * 
 * Implementiert das x402-mcp-middleware Pattern für OAuth 2.1 + PKCE
 * mit direkter RemoteServer Integration.
 * 
 * Verwendung:
 * npm run start:x402-server
 */

async function createX402StyleServer() {
    TestUtils.log( 'Starte X402-Style OAuth MCP Server...', 'info' )

    // OAuth-Setup validieren
    const { isValid, config: oauthConfig, message } = TestUtils.validateOAuthSetup()
    
    if( !isValid ) {
        TestUtils.log( `OAuth-Setup unvollständig: ${message}`, 'error' )
        TestUtils.log( 'Konfiguriere ../oauth-flowmcp.env', 'warn' )
        process.exit( 1 )
    }

    // OAuth-Middleware erstellen (x402-Pattern: direkte Instanz)
    const middleware = OAuthMiddleware.create( oauthConfig )
    
    TestUtils.log( `OAuth-Middleware bereit (${oauthConfig.realm})`, 'success' )

    // Schemas laden für MCP Integration
    let arrayOfSchemas = []
    try {
        const schemaList = await SchemaImporter.loadFromFolder({
            schemaRootFolder: './../schemas/v1.2.0/',
            excludeSchemasWithImports: true,
            excludeSchemasWithRequiredServerParams: true,
            addAdditionalMetaData: true
        })
        
        arrayOfSchemas = schemaList
            .slice( 0, 5 ) // Erste 5 Schemas für Demo
            .map( ( item ) => item.schema )
        
        TestUtils.log( `${arrayOfSchemas.length} MCP Schemas geladen`, 'success' )
    } catch( error ) {
        TestUtils.log( `Schema-Loading fehlgeschlagen: ${error.message}`, 'warn' )
        TestUtils.log( 'Verwende Fallback-Schema', 'info' )
        
        // Fallback Schema (FlowMCP-kompatibel)
        arrayOfSchemas = [{
            namespace: 'oauth-demo',
            name: 'OAuth Demo API',
            description: 'Demo API for OAuth middleware testing',
            flowMCP: '1.2.0',
            root: 'https://api.demo.com',
            requiredServerParams: [],
            routes: {
                demoCall: {
                    method: 'GET',
                    path: '/demo',
                    description: 'OAuth-protected demo call',
                    parameters: {
                        message: { 
                            type: 'string', 
                            description: 'Demo message',
                            required: false,
                            default: 'Hello OAuth!'
                        }
                    },
                    tests: [{
                        description: 'Test demo call',
                        parameters: { message: 'Test message' },
                        expectedStatus: 200
                    }]
                }
            }
        }]
    }

    // FlowMCP Activation Payloads vorbereiten
    const envObject = {} // Leer für Test-Schemas ohne Server-Parameter
    const { activationPayloads } = FlowMCP.prepareActivations({ 
        arrayOfSchemas, 
        envObject 
    })
    
    TestUtils.log( `${activationPayloads.length} FlowMCP Tools aktiviert`, 'success' )

    // RemoteServer mit OAuth-Middleware erstellen
    const remoteServer = new RemoteServer({ silent: false })
    
    // Express App für OAuth-Integration abrufen
    const app = remoteServer.getApp()
    
    // OAuth Well-Known Endpoints (öffentlich)
    app.get( '/.well-known/oauth-authorization-server', middleware.wellKnownAuthorizationServer() )
    app.get( '/.well-known/oauth-protected-resource', middleware.wellKnownProtectedResource() )
    app.get( '/.well-known/jwks.json', middleware.wellKnownJwks() )
    
    // OAuth-Flows für Tests
    app.get( '/auth/login', ( req, res ) => {
        const { authorizationUrl, state } = middleware.initiateAuthorizationCodeFlow({
            scopes: [ 'openid', 'profile', 'mcp:tools' ],
            resourceIndicators: [ `http://localhost:${oauthConfig.testServerPort}` ]
        })
        
        TestUtils.log( `OAuth Flow gestartet: ${state}`, 'info' )
        res.redirect( authorizationUrl )
    })
    
    app.get( '/auth/callback', async ( req, res ) => {
        const { code, state } = req.query
        
        try {
            const { success, tokens } = await middleware.handleAuthorizationCallback({
                code,
                state
            })
            
            if( success ) {
                TestUtils.log( 'OAuth-Login erfolgreich', 'success' )
                res.json({
                    message: 'OAuth 2.1 + PKCE Login erfolgreich',
                    access_token: tokens.access_token,
                    token_type: tokens.token_type,
                    expires_in: tokens.expires_in,
                    instructions: {
                        mcp_endpoint: `http://localhost:${oauthConfig.testServerPort}/mcp/sse`,
                        usage: `Verwende Bearer ${tokens.access_token} für MCP Calls`
                    }
                })
            } else {
                res.status( 400 ).json({ error: 'OAuth-Login fehlgeschlagen' })
            }
        } catch( error ) {
            TestUtils.log( `OAuth-Callback Fehler: ${error.message}`, 'error' )
            res.status( 500 ).json({ error: error.message })
        }
    })

    // Routes Activation Payloads für MCP Server
    const routesActivationPayloads = [{
        routePath: '/mcp',
        protocol: 'sse',
        bearerToken: null, // OAuth-Middleware handled das
        activationPayloads
    }]

    // OAuth-geschütztes /mcp/sse und /mcp/post mit Middleware
    app.use( '/mcp', middleware.mcp() )
    
    // MCP Server starten mit OAuth-Integration
    const PORT = oauthConfig.testServerPort
    
    remoteServer.start({ 
        routesActivationPayloads,
        port: PORT,
        rootUrl: 'http://localhost'
    })
    
    console.log( '' )
    TestUtils.log( 'X402-Style OAuth MCP Server erfolgreich gestartet!', 'success' )
    console.log( '' )
    console.log( `📍 Server: http://localhost:${PORT}` )
    console.log( `🔐 OAuth Login: http://localhost:${PORT}/auth/login` )
    console.log( `🤖 MCP Endpoint: http://localhost:${PORT}/mcp/sse` )
    console.log( '' )
    console.log( '🔑 OAuth Discovery:' )
    console.log( `   Authorization Server: http://localhost:${PORT}/.well-known/oauth-authorization-server` )
    console.log( `   Protected Resource: http://localhost:${PORT}/.well-known/oauth-protected-resource` )
    console.log( `   JWKS: http://localhost:${PORT}/.well-known/jwks.json` )
    console.log( '' )
    console.log( '🛡️  OAuth-geschützte MCP Tools:' )
    activationPayloads.forEach( ( { schema } ) => {
        const routes = Object.keys( schema.routes || {} )
        console.log( `   ${schema.namespace}: ${routes.join( ', ' )}` )
    })
    console.log( '' )
    console.log( '🧪 Integration Test Workflow:' )
    console.log( '   1. Besuche /auth/login für OAuth 2.1 + PKCE Flow' )
    console.log( '   2. Erhalte access_token nach erfolgreichem Login' )
    console.log( '   3. Verwende MCP Client mit Bearer Token:' )
    console.log( `      curl -H "Authorization: Bearer TOKEN" http://localhost:${PORT}/mcp/sse` )
    console.log( '' )
    console.log( '📋 Verfügbare MCP Tools mit OAuth-Schutz:' )
    activationPayloads.forEach( ( { schema } ) => {
        Object.entries( schema.routes || {} ).forEach( ( [ routeName, routeConfig ] ) => {
            console.log( `   ${schema.namespace}_${routeName}: ${routeConfig.description || 'No description'}` )
        })
    })
    console.log( '' )

    return remoteServer
}

// Server starten wenn direkt ausgeführt
if( import.meta.url === `file://${process.argv[1]}` ) {
    createX402StyleServer().catch( ( error ) => {
        TestUtils.log( `X402-Server Start fehlgeschlagen: ${error.message}`, 'error' )
        console.error( error.stack )
        process.exit( 1 )
    })
}

export { createX402StyleServer }