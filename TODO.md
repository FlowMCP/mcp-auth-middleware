# OAuth-Middleware für MCP-Server - Umsetzungsplan

## Übersicht
Entwicklung einer generischen OAuth 2.1-Middleware für MCP-Server mit Keycloak-Integration, die sich nahtlos in das FlowMCP-Ökosystem einbettet.

## Phase 1: Projektstruktur & Grundlagen
### 1.1 Basis-Setup
- [x] `package.json` mit Node.js 22, ES-Module (.mjs), Jest-Tests
- [x] Verzeichnisstruktur: `./src/`, `./tests/`, `./docs/`
- [x] `.gitignore` mit Coverage-Ausschluss
- [x] GitHub Workflow für automatische Tests & Codecov

### 1.2 Kern-Dateien
- [x] `./src/index.mjs` - Hauptexport der OAuthMiddleware-Klasse  
- [x] `./src/OAuthMiddleware.mjs` - Hauptklasse nach CLAUDE.md Standards
- [x] `./src/helpers/TokenValidator.mjs` - JWT-Token-Validierung
- [x] `./src/helpers/KeycloakClient.mjs` - Keycloak-API-Integration

## Phase 2: OAuth 2.1 Implementation
### 2.1 Well-Known Endpoints
- [x] `/.well-known/oauth-authorization-server` Metadata
- [x] `/.well-known/oauth-protected-resource` Metadata  
- [x] `/.well-known/jwks.json` JSON Web Key Set

### 2.2 OAuth-Flows
- [x] Authorization Code Flow mit PKCE
- [x] Client Credentials Flow
- [x] Dynamic Client Registration (RFC 7591)
- [x] Resource Indicators (RFC 8707)

### 2.3 Token-Management
- [x] JWT Access Token Validation
- [x] Scoped Access Control für MCP-Tools
- [x] Token-Audience-Beschränkung
- [x] Refresh Token Support

## Phase 3: Keycloak-Integration  
### 3.1 Keycloak-Client
- [x] Admin REST API Integration
- [ ] Realm-Management
- [x] Client-Konfiguration
- [ ] User-Session-Verwaltung

### 3.2 Konfiguration
- [x] Environment Variables Support
- [x] Keycloak-Server-Discovery
- [ ] Multi-Realm-Support
- [ ] SSL/TLS-Konfiguration

## Phase 4: MCP-Integration
### 4.1 Middleware-Pattern
- [x] Express.js-kompatible Middleware-Funktion
- [x] Request/Response-Interception
- [x] Authorization-Header-Verarbeitung
- [x] Error-Handling nach MCP-Standards

### 4.2 Tool-Scoping
- [x] Fine-grained Permissions (z.B. `mcp:tools:weather`)
- [x] Method-Level-Authorization
- [x] Resource-spezifische Scopes
- [x] Role-Based Access Control (RBAC)

## Phase 5: Testing & Validation
### 5.1 Unit-Tests
- [x] Alle öffentlichen Methoden testen
- [x] Token-Validierung-Tests
- [x] OAuth-Flow-Tests
- [x] Keycloak-Integration-Tests

### 5.2 Integration-Tests
- [ ] End-to-End OAuth-Flows
- [ ] Claude Desktop Kompatibilität
- [ ] Keycloak-Server-Interaktion
- [ ] Error-Scenario-Tests

### 5.3 Coverage
- [x] 100% Test Coverage für `./src/` (Kernmodule)
- [x] Codecov-Integration
- [x] Automatische Coverage-Reports

## Phase 6: Dokumentation
### 6.1 README.md
- [x] Badges, Quickstart, Features
- [x] API-Methoden-Dokumentation
- [x] Code-Beispiele
- [x] Installation & Setup

### 6.2 Keycloak-Setup-Dokumentation
- [x] Realm-Konfiguration
- [x] Client-Setup
- [x] OAuth-Scopes definieren
- [x] Troubleshooting-Guide

### 6.3 Integration-Guide
- [ ] Claude Desktop Setup
- [x] MCP-Server-Integration
- [x] Environment-Konfiguration
- [ ] Production-Deployment

## Phase 7: Deployment & CI/CD
### 7.1 GitHub Integration
- [x] GitHub Actions Workflow
- [x] Automated Testing auf Push/PR
- [ ] Codecov Token Upload
- [ ] Release Automation

### 7.2 NPM Publishing
- [ ] Package-Konfiguration
- [ ] Semantic Versioning
- [ ] Automatische Releases
- [ ] Package-Dokumentation

## Technische Spezifikationen

### OAuth 2.1 Compliance
- **PKCE**: Verpflichtend für alle Clients
- **Resource Indicators**: RFC 8707 Implementation
- **Dynamic Client Registration**: RFC 7591 Support  
- **Security**: Keine Implicit Grant, nur Authorization Code + PKCE

### Keycloak-Requirements
- **Version**: Keycloak 20+ (OAuth 2.1 Support)
- **Realms**: Multi-Realm-Unterstützung
- **Clients**: Confidential + Public Client Support
- **Admin API**: REST-Client für Konfiguration

### Code-Standards (CLAUDE.md)
- **Node.js 22** mit ES-Modulen (.mjs)
- **4 Leerzeichen** Einrückung, keine Semicolons
- **Static Methods** mit Objekt-Parametern
- **Rückgaben als Objekte** mit method-orientierten Keys
- **Private Methods** als Standard (`#private`)

### Validation & Testing
- **Jest** als Test-Framework
- **Strikte Validierung** nach 4-Phasen-Modell
- **Schrittweise Verbesserung** bis alle Tests bestehen
- **Keine Test-Übersprünge** oder Auskommentierungen

Dieser Plan folgt den etablierten FlowMCP-Standards und stellt sicher, dass die OAuth-Middleware generisch und wiederverwendbar für andere MCP-Server-Implementierungen ist.