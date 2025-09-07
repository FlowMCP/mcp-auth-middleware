#!/usr/bin/env node

/**
 * Keycloak Auto-Setup Script (Native Installation)
 * 
 * Automatically configures Keycloak realm, client, user, and scopes
 * for OAuth 2.1 + PKCE integration with MCP servers.
 * 
 * Usage:
 * node scripts/setup-keycloak.mjs
 * 
 * Prerequisites:
 * - Keycloak running on http://localhost:8080
 * - Admin credentials: admin/admin
 */

import fetch from 'node-fetch'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath( import.meta.url )
const __dirname = path.dirname( __filename )

// Configuration
const KEYCLOAK_CONFIG = {
    baseUrl: 'http://localhost:8080',
    adminUsername: 'admin',
    adminPassword: 'admin',
    realm: 'mcp-realm',
    clientId: 'mcp-test-client',
    testUser: {
        username: 'testuser',
        email: 'test@example.com',
        password: 'testpassword123',
        firstName: 'Test',
        lastName: 'User'
    },
    redirectUris: [
        'http://localhost:3000/callback',
        'http://localhost:3000/auth/callback'
    ],
    scopes: [
        { name: 'mcp:tools', description: 'Access to MCP tools' },
        { name: 'mcp:admin', description: 'Administrative access to MCP' },
        { name: 'mcp:tools:weather', description: 'Access to weather-specific MCP tools' }
    ]
}

class KeycloakSetup {
    constructor() {
        this.adminToken = null
        this.clientSecret = null
    }

    async log( message, type = 'info' ) {
        const colors = {
            info: '\x1b[36m',  // Cyan
            success: '\x1b[32m', // Green
            warn: '\x1b[33m',  // Yellow
            error: '\x1b[31m', // Red
            reset: '\x1b[0m'   // Reset
        }
        
        const prefix = {
            info: '📋',
            success: '✅', 
            warn: '⚠️',
            error: '❌'
        }

        console.log( `${colors[type]}${prefix[type]} ${message}${colors.reset}` )
    }

    async makeRequest( url, options = {} ) {
        try {
            const response = await fetch( url, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            })

            if( !response.ok ) {
                const errorText = await response.text()
                throw new Error( `HTTP ${response.status}: ${errorText}` )
            }

            const contentType = response.headers.get( 'content-type' )
            if( contentType && contentType.includes( 'application/json' ) ) {
                return await response.json()
            }
            
            return await response.text()
        } catch( error ) {
            throw new Error( `Request failed: ${error.message}` )
        }
    }

    async getAdminToken() {
        this.log( 'Requesting admin access token...' )
        
        const tokenUrl = `${KEYCLOAK_CONFIG.baseUrl}/realms/master/protocol/openid-connect/token`
        
        const response = await fetch( tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                username: KEYCLOAK_CONFIG.adminUsername,
                password: KEYCLOAK_CONFIG.adminPassword,
                grant_type: 'password',
                client_id: 'admin-cli'
            })
        })

        if( !response.ok ) {
            throw new Error( `Failed to get admin token: ${response.statusText}` )
        }

        const data = await response.json()
        this.adminToken = data.access_token
        
        this.log( 'Admin token acquired successfully', 'success' )
        return this.adminToken
    }

    async checkKeycloakAvailability() {
        this.log( 'Checking Keycloak availability...' )
        
        try {
            const response = await fetch( `${KEYCLOAK_CONFIG.baseUrl}/realms/master/.well-known/openid-configuration` )
            if( response.ok ) {
                this.log( 'Keycloak is running and accessible', 'success' )
                return true
            }
        } catch( error ) {
            this.log( 'Keycloak is not accessible. Please start Keycloak first:', 'error' )
            this.log( '  export KEYCLOAK_ADMIN=admin', 'info' )
            this.log( '  export KEYCLOAK_ADMIN_PASSWORD=admin', 'info' )
            this.log( '  ./bin/kc.sh start-dev --http-port=8080', 'info' )
            return false
        }
    }

    async createRealm() {
        this.log( `Creating realm: ${KEYCLOAK_CONFIG.realm}...` )
        
        const realmUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms`
        
        const realmConfig = {
            realm: KEYCLOAK_CONFIG.realm,
            enabled: true,
            displayName: 'MCP Realm',
            displayNameHtml: '<strong>MCP Realm</strong>',
            registrationAllowed: true,
            loginWithEmailAllowed: true,
            duplicateEmailsAllowed: false,
            resetPasswordAllowed: true,
            editUsernameAllowed: false,
            bruteForceProtected: true,
            permanentLockout: false,
            maxFailureWaitSeconds: 900,
            minimumQuickLoginWaitSeconds: 60,
            waitIncrementSeconds: 60,
            quickLoginCheckMilliSeconds: 1000,
            maxDeltaTimeSeconds: 43200,
            failureFactor: 30
        }

        try {
            await this.makeRequest( realmUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                },
                body: JSON.stringify( realmConfig )
            })
            
            this.log( `Realm '${KEYCLOAK_CONFIG.realm}' created successfully`, 'success' )
        } catch( error ) {
            if( error.message.includes( '409' ) ) {
                this.log( `Realm '${KEYCLOAK_CONFIG.realm}' already exists`, 'warn' )
            } else {
                throw error
            }
        }
    }

    async createClient() {
        this.log( `Creating OAuth client: ${KEYCLOAK_CONFIG.clientId}...` )
        
        const clientUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients`
        
        const clientConfig = {
            clientId: KEYCLOAK_CONFIG.clientId,
            name: 'MCP Test Client',
            description: 'OAuth 2.1 client for MCP server testing',
            enabled: true,
            clientAuthenticatorType: 'client-secret',
            redirectUris: KEYCLOAK_CONFIG.redirectUris,
            webOrigins: [ 'http://localhost:3000' ],
            protocol: 'openid-connect',
            attributes: {
                'pkce.code.challenge.method': 'S256',
                'post.logout.redirect.uris': 'http://localhost:3000'
            },
            standardFlowEnabled: true,
            implicitFlowEnabled: false,
            directAccessGrantsEnabled: true,
            serviceAccountsEnabled: true,
            authorizationServicesEnabled: false,
            publicClient: false,
            frontchannelLogout: false,
            fullScopeAllowed: false
        }

        try {
            await this.makeRequest( clientUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                },
                body: JSON.stringify( clientConfig )
            })
            
            this.log( `Client '${KEYCLOAK_CONFIG.clientId}' created successfully`, 'success' )
            
            // Get client secret
            await this.getClientSecret()
            
        } catch( error ) {
            if( error.message.includes( '409' ) ) {
                this.log( `Client '${KEYCLOAK_CONFIG.clientId}' already exists`, 'warn' )
                await this.getClientSecret()
            } else {
                throw error
            }
        }
    }

    async getClientSecret() {
        this.log( 'Retrieving client secret...' )
        
        // Get client by clientId
        const clientsUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients?clientId=${KEYCLOAK_CONFIG.clientId}`
        const clients = await this.makeRequest( clientsUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.adminToken}`
            }
        })

        if( !clients || clients.length === 0 ) {
            throw new Error( 'Client not found' )
        }

        const clientUuid = clients[0].id

        // Get client secret
        const secretUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients/${clientUuid}/client-secret`
        const secretData = await this.makeRequest( secretUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.adminToken}`
            }
        })

        this.clientSecret = secretData.value
        this.log( 'Client secret retrieved successfully', 'success' )
        
        return this.clientSecret
    }

    async createScopes() {
        this.log( 'Creating custom client scopes...' )
        
        for( const scope of KEYCLOAK_CONFIG.scopes ) {
            await this.createScope( scope )
        }
    }

    async createScope( scope ) {
        const scopeUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/client-scopes`
        
        const scopeConfig = {
            name: scope.name,
            description: scope.description,
            protocol: 'openid-connect',
            attributes: {
                'include.in.token.scope': 'true',
                'display.on.consent.screen': 'true',
                'consent.screen.text': scope.description
            }
        }

        try {
            await this.makeRequest( scopeUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                },
                body: JSON.stringify( scopeConfig )
            })
            
            this.log( `Scope '${scope.name}' created successfully`, 'success' )
        } catch( error ) {
            if( error.message.includes( '409' ) ) {
                this.log( `Scope '${scope.name}' already exists`, 'warn' )
            } else {
                this.log( `Failed to create scope '${scope.name}': ${error.message}`, 'error' )
            }
        }
    }

    async assignScopesToClient() {
        this.log( 'Assigning scopes to client...' )
        
        // Get client UUID
        const clientsUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients?clientId=${KEYCLOAK_CONFIG.clientId}`
        const clients = await this.makeRequest( clientsUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.adminToken}`
            }
        })

        const clientUuid = clients[0].id

        // Get available scopes
        const availableScopesUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients/${clientUuid}/optional-client-scopes`
        const availableScopes = await this.makeRequest( availableScopesUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.adminToken}`
            }
        })

        // Assign our custom scopes
        for( const scopeConfig of KEYCLOAK_CONFIG.scopes ) {
            const scope = availableScopes.find( s => s.name === scopeConfig.name )
            if( scope ) {
                await this.assignScopeToClient( clientUuid, scope.id )
            }
        }
    }

    async assignScopeToClient( clientUuid, scopeId ) {
        const assignUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/clients/${clientUuid}/optional-client-scopes/${scopeId}`
        
        try {
            await this.makeRequest( assignUrl, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                }
            })
        } catch( error ) {
            this.log( `Warning: Could not assign scope: ${error.message}`, 'warn' )
        }
    }

    async createTestUser() {
        this.log( 'Creating test user...' )
        
        const userUrl = `${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}/users`
        
        const userConfig = {
            username: KEYCLOAK_CONFIG.testUser.username,
            email: KEYCLOAK_CONFIG.testUser.email,
            firstName: KEYCLOAK_CONFIG.testUser.firstName,
            lastName: KEYCLOAK_CONFIG.testUser.lastName,
            enabled: true,
            emailVerified: true,
            credentials: [{
                type: 'password',
                value: KEYCLOAK_CONFIG.testUser.password,
                temporary: false
            }]
        }

        try {
            await this.makeRequest( userUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                },
                body: JSON.stringify( userConfig )
            })
            
            this.log( `User '${KEYCLOAK_CONFIG.testUser.username}' created successfully`, 'success' )
        } catch( error ) {
            if( error.message.includes( '409' ) ) {
                this.log( `User '${KEYCLOAK_CONFIG.testUser.username}' already exists`, 'warn' )
            } else {
                throw error
            }
        }
    }

    async generateEnvFile() {
        this.log( 'Generating environment configuration...' )
        
        const envContent = `# OAuth FlowMCP Configuration (Auto-generated)
# Generated on: ${new Date().toISOString()}

# Keycloak Server Configuration  
KEYCLOAK_URL=${KEYCLOAK_CONFIG.baseUrl}
KEYCLOAK_REALM=${KEYCLOAK_CONFIG.realm}
KEYCLOAK_CLIENT_ID=${KEYCLOAK_CONFIG.clientId}
KEYCLOAK_CLIENT_SECRET=${this.clientSecret}

# Keycloak Admin Configuration
KEYCLOAK_ADMIN_USERNAME=${KEYCLOAK_CONFIG.adminUsername}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_CONFIG.adminPassword}

# OAuth Redirect Configuration  
REDIRECT_URI=${KEYCLOAK_CONFIG.redirectUris[0]}

# Test Server Configuration
TEST_SERVER_PORT=3000
TEST_USER_EMAIL=${KEYCLOAK_CONFIG.testUser.email}
TEST_USER_PASSWORD=${KEYCLOAK_CONFIG.testUser.password}
TEST_CLIENT_SCOPE=mcp:tools

# Additional Test Parameters
TEST_REALM_ADMIN_URL=${KEYCLOAK_CONFIG.baseUrl}/admin/realms/${KEYCLOAK_CONFIG.realm}
TEST_TOKEN_ENDPOINT=${KEYCLOAK_CONFIG.baseUrl}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/token
TEST_AUTH_ENDPOINT=${KEYCLOAK_CONFIG.baseUrl}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth
`

        const envPath = path.resolve( __dirname, '../oauth-flowmcp.env' )
        fs.writeFileSync( envPath, envContent )
        
        this.log( `Environment file created: ${envPath}`, 'success' )
    }

    async testConfiguration() {
        this.log( 'Testing OAuth configuration...' )
        
        const wellKnownUrl = `${KEYCLOAK_CONFIG.baseUrl}/realms/${KEYCLOAK_CONFIG.realm}/.well-known/openid-configuration`
        
        try {
            const config = await this.makeRequest( wellKnownUrl, { method: 'GET' })
            
            this.log( 'OAuth configuration is accessible', 'success' )
            this.log( `Authorization Endpoint: ${config.authorization_endpoint}` )
            this.log( `Token Endpoint: ${config.token_endpoint}` )
            this.log( `JWKS URI: ${config.jwks_uri}` )
            
            return true
        } catch( error ) {
            this.log( `Configuration test failed: ${error.message}`, 'error' )
            return false
        }
    }

    async setup() {
        try {
            this.log( 'Starting Keycloak auto-setup...', 'info' )
            this.log( '' )

            // Check if Keycloak is running
            const isAvailable = await this.checkKeycloakAvailability()
            if( !isAvailable ) {
                process.exit( 1 )
            }

            // Get admin token
            await this.getAdminToken()

            // Setup steps
            await this.createRealm()
            await this.createClient()
            await this.createScopes()
            await this.assignScopesToClient()
            await this.createTestUser()
            await this.generateEnvFile()

            // Test configuration
            const testPassed = await this.testConfiguration()

            this.log( '' )
            this.log( '🎉 Keycloak setup completed successfully!', 'success' )
            this.log( '' )
            this.log( 'Configuration Summary:', 'info' )
            this.log( `  Keycloak URL: ${KEYCLOAK_CONFIG.baseUrl}` )
            this.log( `  Realm: ${KEYCLOAK_CONFIG.realm}` )
            this.log( `  Client ID: ${KEYCLOAK_CONFIG.clientId}` )
            this.log( `  Test User: ${KEYCLOAK_CONFIG.testUser.username} / ${KEYCLOAK_CONFIG.testUser.password}` )
            this.log( '' )
            this.log( 'Next Steps:', 'info' )
            this.log( '  1. Start the OAuth server: npm run start:x402-server' )
            this.log( '  2. Visit: http://localhost:3000/auth/login' )
            this.log( '  3. Login with test user credentials' )
            this.log( '  4. Test MCP endpoints with Bearer token' )
            this.log( '' )

        } catch( error ) {
            this.log( `Setup failed: ${error.message}`, 'error' )
            console.error( error.stack )
            process.exit( 1 )
        }
    }
}

// Run setup if called directly
if( import.meta.url === `file://${process.argv[1]}` ) {
    const setup = new KeycloakSetup()
    setup.setup()
}

export { KeycloakSetup }