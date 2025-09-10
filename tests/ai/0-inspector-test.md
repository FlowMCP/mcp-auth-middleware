# AI Inspector Test - OAuth Middleware Login

## Ziel
Automatisierter Browser-Test f�r den MCP Inspector mit OAuth/Bearer Token Authentication

## Voraussetzungen

### 1. Background Jobs starten
```bash
# Terminal 1: MCP Demo Server
npm run start:mcp

# Terminal 2: MCP Inspector
npm run inspect
```

### 2. Umgebungsvariablen (.auth.env)
```env
FIRST_ROUTE_AUTH0_DOMAIN=your-domain.auth0.com
FIRST_ROUTE_AUTH0_CLIENT_ID=your-client-id
FIRST_ROUTE_AUTH0_CLIENT_SECRET=your-client-secret
SECOND_ROUTE_AUTH0_DOMAIN=your-domain2.auth0.com
SECOND_ROUTE_AUTH0_CLIENT_ID=your-client-id-2
SECOND_ROUTE_AUTH0_CLIENT_SECRET=your-client-secret-2
THIRD_ROUTE_BEARER_TOKEN=your-bearer-token
```

## Verf�gbare Routen

### Route 1: First Auth0 Route
- **URL**: `http://localhost:3000/first-route`
- **Auth Type**: OAuth 2.1 (Auth0)
- **Protocol**: SSE
- **Provider**: Auth0
- **Scope**: `openid profile email`
- **Audience**: `http://localhost:3000/first-route`

### Route 2: Second Auth0 Route  
- **URL**: `http://localhost:3000/second-route`
- **Auth Type**: OAuth 2.1 (Auth0)
- **Protocol**: SSE
- **Provider**: Auth0
- **Scope**: `openid profile email`
- **Audience**: `http://localhost:3000/second-route`

### Route 3: Bearer Token Route
- **URL**: `http://localhost:3000/third-route`
- **Auth Type**: Static Bearer Token
- **Protocol**: SSE
- **Token**: Aus Umgebungsvariable `THIRD_ROUTE_BEARER_TOKEN`

## AI Test Ablauf

### Phase 1: Browser Setup
1. **Browser �ffnen**: Playwright Browser starten
2. **Inspector navigieren**: `http://localhost:3000` (Inspector UI)
3. **Screenshot**: Initiale Seite dokumentieren

### Phase 2: Server Connection Setup
1. **Server URL eingeben**: Korrekte MCP Server URL identifizieren
2. **Connection Type w�hlen**: SSE (Server-Sent Events)
3. **Screenshots**: Connection Setup dokumentieren

### Phase 3: Authentication Tests

#### Test A: OAuth Route 1 (/first-route)
1. **Route ausw�hlen**: `/first-route` in Inspector
2. **Auth Type erkennen**: OAuth 2.1 erkannt?
3. **Provider URL**: `https://{FIRST_ROUTE_AUTH0_DOMAIN}` automatisch gesetzt?
4. **Client ID eingeben**: `{FIRST_ROUTE_AUTH0_CLIENT_ID}` aus config
5. **Client Secret eingeben**: `{FIRST_ROUTE_AUTH0_CLIENT_SECRET}` aus config
6. **Scope pr�fen**: `openid profile email` korrekt?
7. **Audience pr�fen**: `http://localhost:3000/first-route` korrekt?
8. **Login Durchf�hrung**: OAuth Flow starten
9. **Auth0 Login**: Browser Redirect zu Auth0, Credentials eingeben
10. **Callback verarbeiten**: Zur�ck zum Inspector, Token erhalten?
11. **Connection Test**: MCP Schema abrufen k�nnen?
12. **Screenshot**: Erfolgreiche Verbindung dokumentieren

#### Test B: OAuth Route 2 (/second-route)
1. **Route wechseln**: `/second-route` ausw�hlen
2. **Auth Type erkennen**: OAuth 2.1 erkannt?
3. **Provider URL**: `https://{SECOND_ROUTE_AUTH0_DOMAIN}` automatisch gesetzt?
4. **Client ID eingeben**: `{SECOND_ROUTE_AUTH0_CLIENT_ID}` aus config
5. **Client Secret eingeben**: `{SECOND_ROUTE_AUTH0_CLIENT_SECRET}` aus config
6. **Scope pr�fen**: `openid profile email` korrekt?
7. **Audience pr�fen**: `http://localhost:3000/second-route` korrekt?
8. **Login Durchf�hrung**: OAuth Flow starten
9. **Auth0 Login**: Browser Redirect zu Auth0, Credentials eingeben
10. **Callback verarbeiten**: Zur�ck zum Inspector, Token erhalten?
11. **Connection Test**: MCP Schema abrufen k�nnen?
12. **Screenshot**: Erfolgreiche Verbindung dokumentieren

#### Test C: Bearer Token Route (/third-route)
1. **Route wechseln**: `/third-route` ausw�hlen
2. **Auth Type erkennen**: Static Bearer erkannt?
3. **Token eingeben**: `{THIRD_ROUTE_BEARER_TOKEN}` aus config
4. **Connection Test**: Direkte Verbindung ohne OAuth Flow
5. **Schema Test**: MCP Schema abrufen k�nnen?
6. **Screenshot**: Erfolgreiche Verbindung dokumentieren

### Phase 4: Functionality Tests
1. **Schema Browsing**: Verf�gbare Tools anzeigen
2. **Tool Execution**: Beispiel-Tool ausf�hren
3. **Response Validation**: Korrekte Antworten erhalten?
4. **Screenshots**: Funktionale Tests dokumentieren

### Phase 5: Cleanup
1. **Connections schlie�en**: Alle aktiven Verbindungen beenden
2. **Browser schlie�en**: Playwright Browser beenden
3. **Background Jobs beenden**: MCP Server + Inspector stoppen

## Erwartete Herausforderungen

### OAuth Flow Komplexit�t
- **Redirect Handling**: Browser muss Auth0 Redirects folgen
- **Credential Input**: Korrekte Auth0 User/Password eingeben
- **Token Extraction**: Access Token aus Callback extrahieren
- **State Validation**: CSRF-Schutz durch State Parameter

### Inspector UI Interaktion
- **Dynamic Loading**: Warten auf AJAX-Responses
- **Form Detection**: Auth-Felder korrekt identifizieren
- **Route Switching**: Zwischen verschiedenen Routen wechseln
- **Error Handling**: Auth-Fehler erkennen und behandeln

### Connection Validation
- **SSE Protocol**: Server-Sent Events korrekt verarbeitet?
- **Schema Loading**: MCP Schemas erfolgreich geladen?
- **Tool Availability**: Verf�gbare Tools angezeigt?
- **Response Format**: JSON-RPC 2.0 korrekt verarbeitet?

## Erfolgskriterien

### Technische Validierung
-  Alle 3 Routen erfolgreich verbunden
-  OAuth Flows ohne Fehler durchlaufen
-  Bearer Token Authentication funktional
-  MCP Schemas erfolgreich geladen
-  Mindestens 1 Tool pro Route ausf�hrbar

### UI/UX Validierung
-  Inspector UI responsive und funktional
-  Auth-Felder korrekt ausgef�llt
-  Fehlermeldungen aussagekr�ftig
-  Screenshots aller kritischen Schritte
-  Cleanup erfolgreich durchgef�hrt

## Debugging Tipps

### Browser Console
- **Network Tab**: HTTP Requests verfolgen
- **Console Log**: JavaScript Fehler erkennen
- **Application Tab**: Local Storage / Session Storage pr�fen

### MCP Server Logs
- **OAuth Responses**: Token Validation Logs
- **Schema Requests**: Successful Schema Loading
- **Tool Executions**: Request/Response Cycles

### Common Issues
- **CORS Errors**: Cross-Origin Request Failures
- **Token Expiry**: Access Token Refresh n�tig
- **Config Mismatch**: Client ID/Secret falsch
- **Network Timeouts**: Langsame Auth0 Responses

## Implementation Notes f�r AI

### Playwright Best Practices
- **Selectors**: Verwende `data-testid` wenn verf�gbar
- **Waits**: `waitForSelector` statt feste Timeouts
- **Screenshots**: Nach jedem kritischen Schritt
- **Error Handling**: Try-catch f�r alle Browser-Aktionen

### OAuth Automation
- **Popup Handling**: Neue Browser-Tabs f�r Auth0
- **Form Detection**: Username/Password Felder finden
- **Redirect Timing**: Warten auf Callback-URL
- **Token Storage**: Access Token aus URL/Storage extrahieren

### Configuration Mapping
```javascript
// Aus config.mjs extrahieren:
const routes = {
    'first-route': {
        domain: envParams.firstRouteAuth0Domain,
        clientId: envParams.firstRouteAuth0ClientId,
        clientSecret: envParams.firstRouteAuth0ClientSecret
    },
    'second-route': {
        domain: envParams.secondRouteAuth0Domain,
        clientId: envParams.secondRouteAuth0ClientId,
        clientSecret: envParams.secondRouteAuth0ClientSecret
    },
    'third-route': {
        token: envParams.thirdRouteBearerToken
    }
}
```