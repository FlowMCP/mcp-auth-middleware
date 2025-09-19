class BearerTestSchema {
    static getRequiredFields() {
        return [
            { name: 'baseUrl', type: 'string', required: true },
            { name: 'routePath', type: 'string', required: true },
            { name: 'bearerToken', type: 'string', required: true }
        ]
    }


    static getOptionalFields() {
        return [
            { name: 'timeout', type: 'number', default: 30000 },
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
            bearerToken: {
                minLength: 8,
                description: 'Must be at least 8 characters long'
            },
            timeout: {
                min: 1000,
                max: 300000,
                description: 'Must be between 1000ms and 300000ms'
            },
            expectedUnauthorizedStatus: {
                min: 400,
                max: 499,
                description: 'Must be a 4xx HTTP status code'
            }
        }
    }


    static getExampleConfig() {
        return {
            baseUrl: 'http://localhost:3000',
            routePath: '/scalekit-route/streamable',
            bearerToken: 'supersecure123',
            timeout: 30000,
            testUnauthorized: true,
            expectedUnauthorizedStatus: 401
        }
    }


    static getMcpMethods() {
        return [
            'initialize',
            'tools/list',
            'tools/call'
        ]
    }
}


export { BearerTestSchema }