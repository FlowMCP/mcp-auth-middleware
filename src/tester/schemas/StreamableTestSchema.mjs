class StreamableTestSchema {
    static getRequiredFields() {
        return [
            { name: 'baseUrl', type: 'string', required: true },
            { name: 'routePath', type: 'string', required: true }
        ]
    }


    static getOptionalFields() {
        return [
            { name: 'timeout', type: 'number', default: 30000 },
            { name: 'expectedStatus', type: 'number', default: 200 }
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
            timeout: {
                min: 1000,
                max: 300000,
                description: 'Must be between 1000ms and 300000ms'
            },
            expectedStatus: {
                min: 100,
                max: 599,
                description: 'Must be a valid HTTP status code'
            }
        }
    }


    static getExampleConfig() {
        return {
            baseUrl: 'http://localhost:3000',
            routePath: '/scalekit-route/streamable',
            timeout: 30000,
            expectedStatus: 200
        }
    }
}


export { StreamableTestSchema }