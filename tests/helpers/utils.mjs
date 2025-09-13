// LEGACY TEST UTILITIES - DEAKTIVIERT
//
// Diese Test-Utilities waren für Keycloak-basierte Tests
// und wurden durch AuthType-spezifische Tests ersetzt.
//
// Nur noch oauth21_auth0 und staticBearer werden unterstützt.
// Diese Datei kann in Zukunft gelöscht werden.

/**
 * @deprecated Legacy Keycloak-based test utilities - no longer supported
 */
export class TestUtils {
    static getServerParams() {
        throw new Error('Legacy Keycloak test utilities are no longer supported. Use AuthType-specific tests instead.')
    }

    static getEnvParams() {
        throw new Error('Legacy Keycloak test utilities are no longer supported. Use AuthType-specific tests instead.')
    }

    static getFullOAuthConfig() {
        throw new Error('Legacy Keycloak test utilities are no longer supported. Use AuthType-specific tests instead.')
    }
}