import fs from 'fs'
import path from 'path'


/**
 * OAuth FlowMCP Test Utilities
 * 
 * Utilities für das Laden von Umgebungsvariablen und Server-Parametern
 * für OAuth-Middleware Tests.
 */
class TestUtils {
    
    /**
     * Lädt Server-Parameter aus einer .env-Datei
     * 
     * @param {Object} params - Parameter-Objekt
     * @param {string} params.path - Pfad zur .env-Datei
     * @param {string[]} params.requiredServerParams - Array der erforderlichen Parameter
     * @returns {Object} Objekt mit geladenen Parametern
     */
    static getServerParams( { path, requiredServerParams } ) {
        const selection = requiredServerParams
            .map( ( serverParam ) => [ serverParam, serverParam ] )

        let result = {}
        
        try {
            result = fs
                .readFileSync( path, 'utf-8' )
                .split( '\n' )
                .map( ( line ) => line.split( '=' ) )
                .reduce( ( acc, [ k, v ] ) => {
                    const find = selection.find( ( [ _, value ] ) => value === k )
                    if( find ) { 
                        acc[ find[0] ] = v?.trim() 
                    }
                    return acc
                }, {} )
        } catch( error ) {
            console.log( `⚠️  Fehler beim Laden der .env-Datei: ${path}` )
            console.log( `   ${error.message}` )
            return {}
        }

        // Prüfe auf fehlende Parameter
        const missingParams = []
        selection.forEach( ( row ) => {
            const [ key, _ ] = row
            if( !result[ key ] ) {
                missingParams.push( key )
                console.log( `Missing ${key} in .env file` )
            }
        } )

        if( missingParams.length > 0 ) {
            console.log( `⚠️  ${missingParams.length} Parameter fehlen in ${path}` )
        }

        return result
    }


    /**
     * Lädt OAuth-spezifische Parameter aus der Standard .env-Datei
     * 
     * @returns {Object} OAuth-Konfigurationsparameter
     */
    static getOAuthParams() {
        const envPath = path.resolve( process.cwd(), '../oauth-flowmcp.env' )
        
        const requiredOAuthParams = [
            'KEYCLOAK_URL',
            'KEYCLOAK_REALM', 
            'KEYCLOAK_CLIENT_ID',
            'KEYCLOAK_CLIENT_SECRET',
            'KEYCLOAK_ADMIN_USERNAME',
            'KEYCLOAK_ADMIN_PASSWORD',
            'REDIRECT_URI'
        ]

        return TestUtils.getServerParams( {
            path: envPath,
            requiredServerParams: requiredOAuthParams
        } )
    }


    /**
     * Lädt Test-spezifische Parameter
     * 
     * @returns {Object} Test-Konfigurationsparameter  
     */
    static getTestParams() {
        const envPath = path.resolve( process.cwd(), '../oauth-flowmcp.env' )
        
        const requiredTestParams = [
            'TEST_SERVER_PORT',
            'TEST_USER_EMAIL',
            'TEST_USER_PASSWORD',
            'TEST_CLIENT_SCOPE'
        ]

        return TestUtils.getServerParams( {
            path: envPath,
            requiredServerParams: requiredTestParams
        } )
    }


    /**
     * Lädt vollständige OAuth-Konfiguration für Tests
     * 
     * @param {Object} options - Optionen
     * @param {boolean} options.silent - Unterdrücke Log-Ausgaben
     * @returns {Object} Vollständige OAuth-Test-Konfiguration
     */
    static getFullOAuthConfig( { silent = false } = {} ) {
        const oauthParams = TestUtils.getOAuthParams()
        const testParams = TestUtils.getTestParams()

        const config = {
            // OAuth Server Konfiguration
            keycloakUrl: oauthParams.KEYCLOAK_URL || 'http://localhost:8080',
            realm: oauthParams.KEYCLOAK_REALM || 'mcp-realm',
            clientId: oauthParams.KEYCLOAK_CLIENT_ID || 'mcp-test-client',
            clientSecret: oauthParams.KEYCLOAK_CLIENT_SECRET,
            redirectUri: oauthParams.REDIRECT_URI || 'http://localhost:3000/callback',
            
            // Admin Konfiguration (für Setup)
            adminUsername: oauthParams.KEYCLOAK_ADMIN_USERNAME || 'admin',
            adminPassword: oauthParams.KEYCLOAK_ADMIN_PASSWORD || 'admin',
            
            // Test Konfiguration
            testServerPort: parseInt( testParams.TEST_SERVER_PORT ) || 3000,
            testUserEmail: testParams.TEST_USER_EMAIL || 'test@example.com',
            testUserPassword: testParams.TEST_USER_PASSWORD || 'testpassword',
            testClientScope: testParams.TEST_CLIENT_SCOPE || 'mcp:tools',
            
            // Middleware Konfiguration
            silent
        }

        if( !silent ) {
            console.log( '⚙️  OAuth Test-Konfiguration geladen:' )
            console.log( `   Keycloak URL: ${config.keycloakUrl}` )
            console.log( `   Realm: ${config.realm}` )
            console.log( `   Client ID: ${config.clientId}` )
            console.log( `   Test Server Port: ${config.testServerPort}` )
            console.log( `   Redirect URI: ${config.redirectUri}` )
            
            // Warnungen für fehlende Parameter
            if( !config.clientSecret ) {
                console.log( '⚠️  KEYCLOAK_CLIENT_SECRET nicht gesetzt' )
            }
        }

        return config
    }


    /**
     * Erstellt OAuth-Middleware-Konfiguration für Tests
     * 
     * @param {Object} overrides - Optionale Überschreibungen
     * @returns {Object} OAuth-Middleware-Konfiguration
     */
    static createOAuthMiddlewareConfig( overrides = {} ) {
        const config = TestUtils.getFullOAuthConfig( { silent: true } )
        
        return {
            keycloakUrl: config.keycloakUrl,
            realm: config.realm,
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            redirectUri: config.redirectUri,
            silent: true,
            ...overrides
        }
    }


    /**
     * Prüft ob alle erforderlichen OAuth-Parameter verfügbar sind
     * 
     * @returns {Object} Validierungsresultat
     */
    static validateOAuthSetup() {
        const config = TestUtils.getFullOAuthConfig( { silent: true } )
        
        const requiredFields = [
            'keycloakUrl', 
            'realm', 
            'clientId', 
            'clientSecret'
        ]
        
        const missing = requiredFields.filter( field => !config[ field ] )
        const isValid = missing.length === 0
        
        return {
            isValid,
            missing,
            config: isValid ? config : null,
            message: isValid 
                ? 'OAuth-Setup vollständig' 
                : `Fehlende Parameter: ${missing.join( ', ' )}`
        }
    }


    /**
     * Hilfsfunktion für Logging in Tests
     * 
     * @param {string} message - Log-Nachricht
     * @param {string} level - Log-Level (info, warn, error)
     */
    static log( message, level = 'info' ) {
        const prefix = {
            info: '📋',
            warn: '⚠️ ',
            error: '❌',
            success: '✅'
        }[ level ] || 'ℹ️ '
        
        console.log( `${prefix} ${message}` )
    }


    /**
     * Wartet eine bestimmte Zeit (für Tests)
     * 
     * @param {number} ms - Millisekunden zum Warten
     */
    static async delay( ms ) {
        return new Promise( resolve => setTimeout( resolve, ms ) )
    }
}

export { TestUtils }