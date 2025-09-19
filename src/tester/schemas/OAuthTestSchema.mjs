class OAuthTestSchema {
    static getRequiredFields() {
        return [
            { name: 'baseUrl', type: 'string', required: true },
            { name: 'routePath', type: 'string', required: true },
            { name: 'oauth21Config', type: 'object', required: true }
        ]
    }


    static getOAuthRequiredFields() {
        return [
            { name: 'providerUrl', type: 'string', required: true },
            { name: 'clientId', type: 'string', required: true },
            { name: 'clientSecret', type: 'string', required: true },
            { name: 'organizationId', type: 'string', required: true },
            { name: 'mcpId', type: 'string', required: true }
        ]
    }


    static getOptionalFields() {
        return [
            { name: 'browserTimeout', type: 'number', default: 90000 },
            { name: 'silent', type: 'boolean', default: false },
            { name: 'testUnauthorized', type: 'boolean', default: true },
            { name: 'expectedUnauthorizedStatus', type: 'number', default: 401 }
        ]
    }


    static getValidationRules() {
        return {
            baseUrl: {
                minLength: 1,
                pattern: /^https?:\/\/.+/,
                description: 'Must be a valid HTTP/HTTPS URL'
            },
            routePath: {
                minLength: 1,
                pattern: /^\/.*$/,
                description: 'Must start with forward slash'
            },
            providerUrl: {
                minLength: 1,
                pattern: /^https?:\/\/.+/,
                description: 'Must be a valid HTTP/HTTPS URL'
            },
            clientId: {
                minLength: 1,
                description: 'Must not be empty'
            },
            clientSecret: {
                minLength: 1,
                description: 'Must not be empty'
            },
            organizationId: {
                minLength: 1,
                description: 'Must not be empty'
            },
            mcpId: {
                minLength: 1,
                description: 'Must not be empty'
            },
            browserTimeout: {
                min: 10000,
                max: 600000,
                description: 'Must be between 10000ms and 600000ms'
            }
        }
    }


    static getExampleConfig() {
        return {
            baseUrl: 'http://localhost:3000',
            routePath: '/scalekit-route/streamable',
            oauth21Config: {
                providerUrl: 'https://auth.scalekit.com',
                clientId: 'client_123456789',
                clientSecret: 'secret_abc123def456',
                organizationId: 'org_987654321',
                mcpId: 'mcp_xyz789'
            },
            browserTimeout: 90000,
            silent: false,
            testUnauthorized: true,
            expectedUnauthorizedStatus: 401
        }
    }


    static getOAuthFlowSteps() {
        return [
            'unauthorized_test',
            'discovery',
            'registration',
            'authorization_prep',
            'browser_auth',
            'token_exchange',
            'token_validation',
            'mcp_initialize',
            'mcp_tools_list',
            'mcp_tool_call'
        ]
    }


    static getMcpMethods() {
        return [
            'initialize',
            'tools/list',
            'tools/call'
        ]
    }
}


export { OAuthTestSchema }