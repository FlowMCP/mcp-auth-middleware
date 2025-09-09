const oauth21Auth0Schema = {
    name: 'OAuth 2.1 with Auth0',
    description: 'OAuth 2.1 implementation for Auth0 provider',
    authType: 'oauth21_auth0',
    
    requiredFields: [
        {
            key: 'providerUrl',
            type: 'string',
            description: 'Auth0 domain URL (e.g., https://tenant.auth0.com)',
            example: 'https://tenant.auth0.com'
        },
        {
            key: 'clientId',
            type: 'string',
            description: 'Auth0 application client ID',
            example: 'abc123def456ghi789'
        },
        {
            key: 'clientSecret',
            type: 'string',
            description: 'Auth0 application client secret',
            example: 'secret_abc123def456'
        },
        {
            key: 'scope',
            type: 'string',
            description: 'OAuth scopes to request',
            example: 'openid profile email'
        },
        {
            key: 'audience',
            type: 'string',
            description: 'Auth0 API audience identifier',
            example: 'https://api.example.com'
        }
    ],
    
    optionalFields: [
        {
            key: 'redirectUri',
            type: 'string',
            description: 'OAuth redirect URI (auto-generated if not provided)',
            example: 'https://localhost:3000/api/auth/callback'
        },
        {
            key: 'responseType',
            type: 'string',
            description: 'OAuth response type',
            default: 'code',
            allowedValues: [ 'code' ]
        },
        {
            key: 'grantType',
            type: 'string',
            description: 'OAuth grant type',
            default: 'authorization_code',
            allowedValues: [ 'authorization_code' ]
        },
        {
            key: 'tokenEndpoint',
            type: 'string',
            description: 'Custom token endpoint (auto-discovered if not provided)',
            example: 'https://tenant.auth0.com/oauth/token'
        },
        {
            key: 'userInfoEndpoint',
            type: 'string',
            description: 'Custom userinfo endpoint (auto-discovered if not provided)',
            example: 'https://tenant.auth0.com/userinfo'
        }
    ],
    
    defaults: {
        responseType: 'code',
        grantType: 'authorization_code',
        scope: 'openid profile email'
    },
    
    validation: {
        providerUrl: {
            pattern: /^https:\/\/[a-zA-Z0-9.-]+\.auth0\.com$/,
            message: 'providerUrl must be a valid Auth0 domain (https://tenant.auth0.com)'
        },
        clientId: {
            minLength: 10,
            message: 'clientId must be at least 10 characters long'
        },
        clientSecret: {
            minLength: 10,
            message: 'clientSecret must be at least 10 characters long'
        },
        scope: {
            pattern: /^[a-zA-Z0-9_\s:.-]+$/,
            message: 'scope must contain only valid OAuth scope characters'
        }
    }
}

export { oauth21Auth0Schema }