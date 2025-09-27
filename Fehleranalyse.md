# OAuth 2.1 MCP Server - Fehleranalyse und Lösungsdokumentation

## Problembeschreibung

### Symptome
- OAuth-Server unter `https://community.flowmcp.org/scalekit/streamable` wird von MCP-Clients nicht erkannt
- Vergleichsserver `https://schemas.flowmcp.workers.dev/sse` funktioniert korrekt
- Fehlermeldung: Clients können OAuth-Discovery nicht abschließen

### Betroffene Systeme
- **Hauptserver**: community.flowmcp.org (Node.js/Express mit mcpAuthMiddleware)
- **MCP-Version**: 2.1
- **OAuth-Standard**: OAuth 2.1 mit RFC 9728 (Protected Resource Metadata)

## Technische Analyse

### 1. HTTP-Response-Vergleich

#### Nicht funktionierender Server (community.flowmcp.org)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="OAuth", resource_metadata="https://community.flowmcp.org/scalekit/streamable/.well-known/oauth-protected-resource"
```

#### Funktionierender Server (schemas.flowmcp.workers.dev)
```http
HTTP/2 401
www-authenticate: Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"
```

### 2. Kernproblem: URL-Mismatch bei OAuth-Discovery

#### Fehlerhafter Ablauf
1. Client ruft auf: `GET /scalekit/streamable`
2. Server antwortet mit: `401` und `WWW-Authenticate` Header
3. Header verweist auf: `/scalekit/streamable/.well-known/oauth-protected-resource`
4. Client ruft Metadata-URL auf
5. **FEHLER**: Metadata-Endpoint existiert nicht unter dieser URL
6. Stattdessen: Server registriert Endpoint global unter `/.well-known/oauth-protected-resource`
7. **RESULTAT**: 401-Loop, da Metadata-URL selbst authentifiziert ist

#### Architektur-Konflikt
```
Registrierte Route:    /.well-known/oauth-protected-resource
Referenzierte Route:   /scalekit/streamable/.well-known/oauth-protected-resource
                       ^^^^^^^^^^^^^^^^^^^^ (fehlendes Präfix)
```

### 3. MCP 2.1 Spezifikation - Anforderungen

Laut OAuth 2.1 und RFC 9728 MUSS ein MCP-Server:

1. **Metadata-Endpoint bereitstellen**
   - MUSS unter `.well-known/oauth-protected-resource` erreichbar sein
   - MUSS **OHNE Authentifizierung** zugänglich sein (kritisch!)
   - MUSS valides JSON zurückgeben

2. **Metadata-Struktur**
   ```json
   {
     "authorization_servers": ["https://auth-server.example.com"],
     "bearer_methods_supported": ["header"],
     "resource": "https://resource.example.com",
     "resource_documentation": "https://docs.example.com",
     "scopes_supported": ["read", "write"]
   }
   ```

3. **WWW-Authenticate Header**
   - Bei 401-Response MUSS `resource_metadata` auf gültigen Metadata-Endpoint zeigen
   - URL im Header MUSS tatsächlich existieren und erreichbar sein

## Lösungsansatz

### Option 1: Minimaler Eingriff (EMPFOHLEN)
**Änderung in**: `/node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs`

#### Zeile 69-72 (ALT)
```javascript
router.get( '/.well-known/oauth-protected-resource', ( _req, res ) => {
    return this.#handleWellKnownEndpoint( { res } )
} )
```

#### Zeile 69-75 (NEU)
```javascript
// OAuth Well-Known Endpoint (route-specific to match WWW-Authenticate header)
// Extract base path from attached routes to register metadata endpoint correctly
const basePath = this.#attachedRoutes[0] ? this.#attachedRoutes[0].replace(/\/streamable$|\/sse$/, '') : ''
router.get( `${basePath}/.well-known/oauth-protected-resource`, ( _req, res ) => {
    return this.#handleWellKnownEndpoint( { res } )
} )
```

### Option 2: WWW-Authenticate Header anpassen
**Änderung in**: Zeile 182-184

#### ALT
```javascript
#buildWWWAuthenticateHeader() {
    return `Bearer realm="OAuth", resource_metadata="${this.#expectedAudience}/.well-known/oauth-protected-resource"`
}
```

#### NEU
```javascript
#buildWWWAuthenticateHeader() {
    const baseUrl = new URL(this.#expectedAudience).origin
    return `Bearer realm="OAuth", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`
}
```

## Implementierungsanleitung für AI

### Schritt 1: Problem verifizieren
```bash
# Test ob Metadata-Endpoint existiert (sollte 404 oder 401 zurückgeben)
curl -I https://community.flowmcp.org/scalekit/streamable/.well-known/oauth-protected-resource

# Test ob globaler Endpoint existiert (könnte 200 zurückgeben)
curl -I https://community.flowmcp.org/.well-known/oauth-protected-resource
```

### Schritt 2: Datei lokalisieren
```bash
# Finde die ScaleKitMiddleware.mjs Datei
find . -name "ScaleKitMiddleware.mjs" -type f
# Erwarteter Pfad: ./node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs
```

### Schritt 3: Backup erstellen
```bash
cp node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs \
   node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs.backup
```

### Schritt 4: Änderung implementieren
1. Öffne Datei: `node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs`
2. Suche nach Methode: `router()`
3. Finde Zeile mit: `router.get( '/.well-known/oauth-protected-resource'`
4. Implementiere Option 1 (siehe oben)

### Schritt 5: Server neu starten
```bash
# Entwicklung
npm run dev

# Produktion
pm2 restart community-server
```

### Schritt 6: Verifikation
```bash
# Test 1: Metadata-Endpoint sollte jetzt JSON zurückgeben
curl https://community.flowmcp.org/scalekit/streamable/.well-known/oauth-protected-resource

# Erwartete Response (HTTP 200):
{
  "authorization_servers": [...],
  "bearer_methods_supported": ["header"],
  "resource": "https://community.flowmcp.org/scalekit/streamable",
  ...
}

# Test 2: Hauptendpoint sollte korrekten WWW-Authenticate Header haben
curl -I https://community.flowmcp.org/scalekit/streamable

# Erwarteter Header:
WWW-Authenticate: Bearer realm="OAuth", resource_metadata="https://community.flowmcp.org/scalekit/streamable/.well-known/oauth-protected-resource"
```

## Wichtige Hinweise

### Warum Option 1 besser ist
1. **Konsistenz**: URL im WWW-Authenticate Header stimmt mit tatsächlicher Route überein
2. **MCP-Konformität**: Jede geschützte Ressource hat eigenen Metadata-Endpoint
3. **Skalierbarkeit**: Funktioniert für mehrere OAuth-geschützte Routes

### Potenzielle Nebenwirkungen
- Änderung in `node_modules` geht bei `npm install` verloren
- Lösung: Fork von mcpAuthMiddleware erstellen oder Patch-Package verwenden

### Langfristige Lösung
1. Pull Request an mcpAuthMiddleware-Repository
2. Konfigurationsoption für Metadata-Endpoint-Pfad hinzufügen
3. Tests für verschiedene Route-Konfigurationen

## Zusammenfassung für AI-Implementierung

**AUFGABE**: OAuth-Discovery-Endpoint korrigieren

**PROBLEM**: Metadata-URL existiert nicht unter referenziertem Pfad

**LÖSUNG**: Route-spezifischen Metadata-Endpoint registrieren

**DATEIEN**:
- Hauptdatei: `node_modules/mcpAuthMiddleware/src/authTypes/ScaleKitMiddleware.mjs`
- Zeilen: 69-72

**ÄNDERUNG**: 3 Zeilen Code hinzufügen (siehe Option 1)

**VERIFIKATION**:
1. `curl` auf Metadata-URL muss JSON zurückgeben (nicht 401)
2. MCP-Client muss Server erfolgreich erkennen

**ZEITAUFWAND**: ~5 Minuten

**RISIKO**: Minimal (nur Route-Registrierung geändert)