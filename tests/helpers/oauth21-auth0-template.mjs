// Complete OAuth21 Auth0 Configuration Template
// All fields are REQUIRED after defensive defaults removal

const completeOAuth21Auth0Config = {
    authType: 'oauth21_auth0',
    providerUrl: 'https://tenant.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    scope: 'openid profile email',
    audience: 'https://api.example.com',
    realm: 'test-realm',
    authFlow: 'authorization_code',
    requiredScopes: [ 'openid', 'profile', 'email' ],
    requiredRoles: [ 'user', 'admin' ]
}

// Minimal valid configuration for quick tests
const minimalOAuth21Auth0Config = {
    authType: 'oauth21_auth0',
    providerUrl: 'https://test.auth0.com',
    clientId: 'minimal-client',
    clientSecret: 'minimal-secret',
    scope: 'openid',
    audience: 'https://api.test.com',
    realm: 'minimal-realm',
    authFlow: 'authorization_code',
    requiredScopes: [],
    requiredRoles: []
}

// Route configuration template for integration tests
const completeRouteConfig = {
    '/test-route': {
        authType: 'oauth21_auth0',
        providerUrl: 'https://tenant.auth0.com',
        clientId: 'route-client-id',
        clientSecret: 'route-client-secret',
        scope: 'openid profile email',
        audience: 'https://api.example.com/test-route',
        realm: 'test-route-realm',
        authFlow: 'authorization_code',
        requiredScopes: [ 'read:test' ],
        requiredRoles: [ 'test-user' ]
    }
}

export {
    completeOAuth21Auth0Config,
    minimalOAuth21Auth0Config,
    completeRouteConfig
}