const staticBearerSchema = {
    name: 'Static Bearer Token',
    description: 'Simple static bearer token authentication',
    authType: 'staticBearer',
    
    requiredFields: [
        {
            key: 'token',
            type: 'string',
            description: 'The static bearer token (without Bearer prefix)',
            example: 'abc123def456ghi789'
        }
    ],
    
    optionalFields: [],
    
    defaults: {},
    
    validation: {
        token: {
            minLength: 8,
            pattern: /^(?!Bearer\s).+/i,
            message: 'token must not start with "Bearer" and be at least 8 characters'
        }
    }
}

export { staticBearerSchema }