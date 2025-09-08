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
     * @deprecated Use getEnvParams() instead
     * Legacy method for backward compatibility
     */
    static getServerParams( { path, requiredServerParams } ) {
        const selection = requiredServerParams
            .map( ( serverParam ) => [ serverParam, serverParam ] )
        
        return TestUtils.getEnvParams( { envPath: path, selection } )
    }


    /**
     * Lädt Umgebungsparameter aus einer .env-Datei mit flexibler Selection
     * 
     * @param {Object} params - Parameter-Objekt
     * @param {string} params.envPath - Pfad zur .env-Datei
     * @param {Array} params.selection - Array von [outputKey, envKey] Zuordnungen
     * @returns {Object} Objekt mit geladenen Parametern
     */
    static getEnvParams( { envPath, selection } ) {
        let result = {}
        
        try {
            result = fs
                .readFileSync( envPath, 'utf-8' )
                .split( '\n' )
                .map( ( line ) => line.split( '=' ) )
                .reduce( ( acc, [ k, v ] ) => {
                    const find = selection.find( ( [ _, envKey ] ) => envKey === k )
                    if( find ) { 
                        acc[ find[0] ] = v?.trim() 
                    }
                    return acc
                }, {} )
        } catch( error ) {
            return {}
        }

        // Prüfe auf fehlende Parameter
        const missingParams = []
        selection.forEach( ( [ outputKey, envKey ] ) => {
            if( !result[ outputKey ] ) {
                missingParams.push( outputKey )
            }
        } )

        return result
    }


    /**
     * @deprecated Use getEnvParams() with selection array instead
     * Legacy method for Auth0 parameters
     */
    static getAuth0Params() {
        const envPath = path.resolve( process.cwd(), '../.auth.env' )
        
        const requiredAuth0Params = [
            'AUTH0_DOMAIN',
            'AUTH0_CLIENT_ID',
            'AUTH0_CLIENT_SECRET'
        ]

        return TestUtils.getServerParams( {
            path: envPath,
            requiredServerParams: requiredAuth0Params
        } )
    }


    /**
     * @deprecated Use getEnvParams() with selection array instead
     * Legacy method for OAuth parameters
     */
    static getOAuthParams() {
        const envPath = path.resolve( process.cwd(), '../.auth.env' )
        
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
     * @deprecated Use getEnvParams() with selection array instead
     * Legacy method for test parameters
     */
    static getTestParams() {
        const envPath = path.resolve( process.cwd(), '../.auth.env' )
        
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
        
        // Logging disabled in tests
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