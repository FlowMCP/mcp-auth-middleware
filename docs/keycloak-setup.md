# Keycloak Setup Guide für OAuth-Middleware

Diese Anleitung beschreibt, wie Keycloak konfiguriert wird, um mit der OAuth 2.1 Middleware für MCP-Server zu funktionieren.

## Voraussetzungen

- Keycloak 20+ (für OAuth 2.1 Support)
- Laufende Keycloak-Instanz auf `oauth.flowmcp.org` oder lokal
- Admin-Zugriff auf Keycloak

## Schritt 1: Realm erstellen

1. **Admin Console öffnen**: Navigiere zu `https://oauth.flowmcp.org/admin` oder `http://localhost:8080/admin`
2. **Neuen Realm erstellen**:
   - Klicke auf "Create realm"
   - Name: `mcp-realm` (oder gewünschter Name)
   - Display Name: `MCP OAuth Realm`
   - Aktiviert: `ON`

## Schritt 2: OAuth Client konfigurieren

### Confidential Client (für Server-to-Server)

1. **Client erstellen**:
   - Navigiere zu `Clients` → `Create client`
   - Client Type: `OpenID Connect`
   - Client ID: `mcp-server-client`
   - Name: `MCP Server Client`
   - Always display in UI: `OFF`

2. **Client Settings**:
   ```yaml
   # General Settings
   Client authentication: ON
   Authorization: ON
   Authentication flow:
     - Standard flow: ON
     - Direct access grants: OFF
     - Implicit flow: OFF
     - Service accounts roles: ON
     - OAuth 2.0 Device Authorization Grant: OFF
   ```

3. **OAuth 2.1 Compliance**:
   - Gehe zu `Advanced Settings`
   - Proof Key for Code Exchange Code Challenge Method: `S256`
   - Use Refresh Tokens: `ON`
   - Use Refresh Tokens For Client Credentials Grant: `ON`

### Public Client (für Desktop Apps wie Claude)

1. **Public Client erstellen**:
   - Client ID: `mcp-desktop-client`
   - Client authentication: `OFF`
   - Standard flow: `ON`
   - Direct access grants: `OFF`
   - Implicit flow: `OFF`

2. **Redirect URIs**:
   ```
   http://localhost:*
   https://claude.ai/oauth/callback
   urn:ietf:wg:oauth:2.0:oob
   ```

## Schritt 3: Scopes und Rollen definieren

### Client Scopes erstellen

1. **Navigiere zu Client Scopes**:
   - `Client Scopes` → `Create client scope`

2. **MCP-spezifische Scopes**:

   **Scope: `mcp:tools`**
   ```yaml
   Name: mcp:tools
   Description: Access to MCP tools
   Type: Default
   Include in token scope: ON
   ```

   **Scope: `mcp:resources`**
   ```yaml
   Name: mcp:resources  
   Description: Access to MCP resources
   Type: Default
   Include in token scope: ON
   ```

   **Scope: `mcp:tools:weather`**
   ```yaml
   Name: mcp:tools:weather
   Description: Access to weather tools only
   Type: Optional
   Include in token scope: ON
   ```

### Client Scope Zuordnung

1. **Zu Clients hinzufügen**:
   - Gehe zu `Clients` → `mcp-server-client` → `Client scopes`
   - `Add client scopes`
   - Füge alle MCP-Scopes als `Default` hinzu

## Schritt 4: Benutzer und Gruppen

### Test-Benutzer erstellen

1. **Benutzer erstellen**:
   - `Users` → `Create new user`
   - Username: `mcp-test-user`
   - Email: `test@flowmcp.org`
   - First name: `MCP`
   - Last name: `User`
   - Enabled: `ON`
   - Email verified: `ON`

2. **Passwort setzen**:
   - `Credentials` Tab
   - Passwort: `SecurePassword123!`
   - Temporary: `OFF`

### Gruppen für RBAC

1. **MCP-Gruppen erstellen**:

   **Gruppe: `mcp-admins`**
   - Vollzugriff auf alle MCP-Tools und -Ressourcen

   **Gruppe: `mcp-users`**
   - Basis-Zugriff auf MCP-Tools

   **Gruppe: `mcp-weather-users`**
   - Nur Zugriff auf Weather-Tools

## Schritt 5: Token-Konfiguration

### Access Token Lebensdauer

1. **Realm Settings** → `Tokens`:
   ```yaml
   Access Token Lifespan: 15 minutes
   Access Token Lifespan For Implicit Flow: 15 minutes  
   Client login timeout: 1 minute
   Login timeout: 30 minutes
   Login action timeout: 5 minutes
   ```

### Token Format und Validation

1. **Client Settings** → `Advanced`:
   ```yaml
   Access Token Signature Algorithm: RS256
   Use Refresh Tokens: ON
   Revoke Refresh Token: ON
   ```

## Schritt 6: Well-Known Endpoints verifizieren

Nach der Konfiguration sollten folgende Endpoints verfügbar sein:

```bash
# Authorization Server Metadata
curl https://oauth.flowmcp.org/realms/mcp-realm/.well-known/openid_configuration

# JWKS Endpoint  
curl https://oauth.flowmcp.org/realms/mcp-realm/protocol/openid-connect/certs
```

## Schritt 7: Environment Variablen

Für die OAuth-Middleware benötigst du folgende Environment-Variablen:

```env
KEYCLOAK_URL=https://oauth.flowmcp.org
KEYCLOAK_REALM=mcp-realm
KEYCLOAK_CLIENT_ID=mcp-server-client
KEYCLOAK_CLIENT_SECRET=your-client-secret-from-keycloak
```

## Schritt 8: Client Secret abrufen

1. **Client Secret holen**:
   - `Clients` → `mcp-server-client` → `Credentials`
   - Kopiere den `Client secret`
   - Nutze diesen als `KEYCLOAK_CLIENT_SECRET`

## Validation und Tests

### OAuth Flow testen

```bash
# Authorization Code Flow mit PKCE
curl -X GET "https://oauth.flowmcp.org/realms/mcp-realm/protocol/openid-connect/auth?client_id=mcp-desktop-client&response_type=code&redirect_uri=http://localhost:3000/callback&scope=openid+mcp:tools&code_challenge=CHALLENGE&code_challenge_method=S256"
```

### Token introspection testen

```bash  
curl -X POST "https://oauth.flowmcp.org/realms/mcp-realm/protocol/openid-connect/token/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=mcp-server-client&client_secret=CLIENT_SECRET"
```

## Troubleshooting

### Häufige Probleme

1. **"Client not found"**:
   - Überprüfe Client ID und Realm Namen
   - Stelle sicher, dass Client aktiviert ist

2. **"Invalid redirect URI"**:
   - Füge korrekte Redirect URIs in Client Settings hinzu
   - Überprüfe genaue URL-Matching

3. **"Access denied"**:
   - Überprüfe Client Scopes Zuordnung
   - Stelle sicher, dass Benutzer entsprechende Gruppen/Rollen hat

4. **"Token validation fails"**:
   - Überprüfe JWKS URI Erreichbarkeit
   - Stelle sicher, dass Token nicht abgelaufen ist
   - Überprüfe Audience und Issuer Claims

### Logs überprüfen

```bash
# Keycloak Server Logs
docker logs keycloak-container

# OAuth-Middleware Debug
NODE_ENV=development npm start
```

## Produktions-Überlegungen

1. **SSL/TLS**: Immer HTTPS in Produktion verwenden
2. **Token Rotation**: Kurze Access Token Lifespans
3. **Rate Limiting**: JWKS Requests limitieren
4. **Monitoring**: Token-Usage und Failed Attempts überwachen
5. **Backup**: Regelmäßige Realm-Exports

Diese Konfiguration stellt sicher, dass die OAuth-Middleware sicher mit Keycloak kommunizieren kann und alle OAuth 2.1 Standards erfüllt werden.