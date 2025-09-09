import { oauth21Auth0Schema } from '../../../../src/authTypes/oauth21_auth0/OAuth21Auth0Schema.mjs'

describe('OAuth21Auth0Schema', () => {
    describe('schema structure', () => {
        test('has correct basic metadata', () => {
            expect(oauth21Auth0Schema.name).toBe('OAuth 2.1 with Auth0')
            expect(oauth21Auth0Schema.description).toBe('OAuth 2.1 implementation for Auth0 provider')
            expect(oauth21Auth0Schema.authType).toBe('oauth21_auth0')
        })

        test('has all required structure properties', () => {
            expect(oauth21Auth0Schema).toHaveProperty('name')
            expect(oauth21Auth0Schema).toHaveProperty('description')
            expect(oauth21Auth0Schema).toHaveProperty('authType')
            expect(oauth21Auth0Schema).toHaveProperty('requiredFields')
            expect(oauth21Auth0Schema).toHaveProperty('optionalFields')
            expect(oauth21Auth0Schema).toHaveProperty('defaults')
            expect(oauth21Auth0Schema).toHaveProperty('validation')
        })

        test('has arrays for field definitions', () => {
            expect(Array.isArray(oauth21Auth0Schema.requiredFields)).toBe(true)
            expect(Array.isArray(oauth21Auth0Schema.optionalFields)).toBe(true)
        })

        test('has objects for defaults and validation', () => {
            expect(typeof oauth21Auth0Schema.defaults).toBe('object')
            expect(typeof oauth21Auth0Schema.validation).toBe('object')
        })
    })

    describe('required fields', () => {
        test('has correct number of required fields', () => {
            expect(oauth21Auth0Schema.requiredFields).toHaveLength(5)
        })

        test('includes providerUrl field', () => {
            const providerUrlField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'providerUrl')
            
            expect(providerUrlField).toBeDefined()
            expect(providerUrlField.type).toBe('string')
            expect(providerUrlField.description).toContain('Auth0 domain URL')
            expect(providerUrlField.example).toBe('https://tenant.auth0.com')
        })

        test('includes clientId field', () => {
            const clientIdField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'clientId')
            
            expect(clientIdField).toBeDefined()
            expect(clientIdField.type).toBe('string')
            expect(clientIdField.description).toContain('Auth0 application client ID')
            expect(clientIdField.example).toBe('abc123def456ghi789')
        })

        test('includes clientSecret field', () => {
            const clientSecretField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'clientSecret')
            
            expect(clientSecretField).toBeDefined()
            expect(clientSecretField.type).toBe('string')
            expect(clientSecretField.description).toContain('Auth0 application client secret')
            expect(clientSecretField.example).toBe('secret_abc123def456')
        })

        test('includes scope field', () => {
            const scopeField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'scope')
            
            expect(scopeField).toBeDefined()
            expect(scopeField.type).toBe('string')
            expect(scopeField.description).toContain('OAuth scopes to request')
            expect(scopeField.example).toBe('openid profile email')
        })

        test('includes audience field', () => {
            const audienceField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'audience')
            
            expect(audienceField).toBeDefined()
            expect(audienceField.type).toBe('string')
            expect(audienceField.description).toContain('Auth0 API audience identifier')
            expect(audienceField.example).toBe('https://api.example.com')
        })

        test('all required fields have necessary properties', () => {
            oauth21Auth0Schema.requiredFields.forEach(field => {
                expect(field).toHaveProperty('key')
                expect(field).toHaveProperty('type')
                expect(field).toHaveProperty('description')
                expect(field).toHaveProperty('example')
                expect(typeof field.key).toBe('string')
                expect(typeof field.type).toBe('string')
                expect(typeof field.description).toBe('string')
                expect(typeof field.example).toBe('string')
            })
        })
    })

    describe('optional fields', () => {
        test('has correct number of optional fields', () => {
            expect(oauth21Auth0Schema.optionalFields).toHaveLength(5)
        })

        test('includes redirectUri field', () => {
            const redirectUriField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'redirectUri')
            
            expect(redirectUriField).toBeDefined()
            expect(redirectUriField.type).toBe('string')
            expect(redirectUriField.description).toContain('OAuth redirect URI')
            expect(redirectUriField.example).toBe('https://localhost:3000/api/auth/callback')
        })

        test('includes responseType field with defaults and allowed values', () => {
            const responseTypeField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'responseType')
            
            expect(responseTypeField).toBeDefined()
            expect(responseTypeField.type).toBe('string')
            expect(responseTypeField.description).toContain('OAuth response type')
            expect(responseTypeField.default).toBe('code')
            expect(responseTypeField.allowedValues).toEqual(['code'])
        })

        test('includes grantType field with defaults and allowed values', () => {
            const grantTypeField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'grantType')
            
            expect(grantTypeField).toBeDefined()
            expect(grantTypeField.type).toBe('string')
            expect(grantTypeField.description).toContain('OAuth grant type')
            expect(grantTypeField.default).toBe('authorization_code')
            expect(grantTypeField.allowedValues).toEqual(['authorization_code'])
        })

        test('includes tokenEndpoint field', () => {
            const tokenEndpointField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'tokenEndpoint')
            
            expect(tokenEndpointField).toBeDefined()
            expect(tokenEndpointField.type).toBe('string')
            expect(tokenEndpointField.description).toContain('Custom token endpoint')
            expect(tokenEndpointField.example).toBe('https://tenant.auth0.com/oauth/token')
        })

        test('includes userInfoEndpoint field', () => {
            const userInfoEndpointField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'userInfoEndpoint')
            
            expect(userInfoEndpointField).toBeDefined()
            expect(userInfoEndpointField.type).toBe('string')
            expect(userInfoEndpointField.description).toContain('Custom userinfo endpoint')
            expect(userInfoEndpointField.example).toBe('https://tenant.auth0.com/userinfo')
        })

        test('all optional fields have necessary properties', () => {
            oauth21Auth0Schema.optionalFields.forEach(field => {
                expect(field).toHaveProperty('key')
                expect(field).toHaveProperty('type')
                expect(field).toHaveProperty('description')
                expect(typeof field.key).toBe('string')
                expect(typeof field.type).toBe('string')
                expect(typeof field.description).toBe('string')
            })
        })
    })

    describe('defaults', () => {
        test('has correct default values', () => {
            expect(oauth21Auth0Schema.defaults).toEqual({
                responseType: 'code',
                grantType: 'authorization_code',
                scope: 'openid profile email'
            })
        })

        test('default values match optional field defaults', () => {
            const responseTypeField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'responseType')
            const grantTypeField = oauth21Auth0Schema.optionalFields.find(field => field.key === 'grantType')
            
            expect(oauth21Auth0Schema.defaults.responseType).toBe(responseTypeField.default)
            expect(oauth21Auth0Schema.defaults.grantType).toBe(grantTypeField.default)
        })

        test('includes scope default matching required field example', () => {
            const scopeField = oauth21Auth0Schema.requiredFields.find(field => field.key === 'scope')
            
            expect(oauth21Auth0Schema.defaults.scope).toBe(scopeField.example)
        })
    })

    describe('validation rules', () => {
        test('has validation rules for required fields', () => {
            expect(oauth21Auth0Schema.validation).toHaveProperty('providerUrl')
            expect(oauth21Auth0Schema.validation).toHaveProperty('clientId')
            expect(oauth21Auth0Schema.validation).toHaveProperty('clientSecret')
            expect(oauth21Auth0Schema.validation).toHaveProperty('scope')
        })

        describe('providerUrl validation', () => {
            test('has correct pattern and message', () => {
                const providerUrlValidation = oauth21Auth0Schema.validation.providerUrl
                
                expect(providerUrlValidation.pattern).toBeInstanceOf(RegExp)
                expect(providerUrlValidation.message).toContain('valid Auth0 domain')
                expect(providerUrlValidation.message).toContain('https://tenant.auth0.com')
            })

            test('pattern validates correct Auth0 URLs', () => {
                const pattern = oauth21Auth0Schema.validation.providerUrl.pattern
                
                expect(pattern.test('https://tenant.auth0.com')).toBe(true)
                expect(pattern.test('https://my-company.auth0.com')).toBe(true)
                expect(pattern.test('https://test-env.auth0.com')).toBe(true)
            })

            test('pattern rejects invalid URLs', () => {
                const pattern = oauth21Auth0Schema.validation.providerUrl.pattern
                
                expect(pattern.test('http://tenant.auth0.com')).toBe(false) // HTTP instead of HTTPS
                expect(pattern.test('https://accounts.google.com')).toBe(false) // Not Auth0 domain
                expect(pattern.test('https://tenant.auth0.org')).toBe(false) // Wrong TLD
                expect(pattern.test('tenant.auth0.com')).toBe(false) // Missing protocol
                expect(pattern.test('https://auth0.com')).toBe(false) // Missing tenant
            })
        })

        describe('clientId validation', () => {
            test('has correct minLength and message', () => {
                const clientIdValidation = oauth21Auth0Schema.validation.clientId
                
                expect(clientIdValidation.minLength).toBe(10)
                expect(clientIdValidation.message).toContain('clientId must be at least 10 characters')
            })
        })

        describe('clientSecret validation', () => {
            test('has correct minLength and message', () => {
                const clientSecretValidation = oauth21Auth0Schema.validation.clientSecret
                
                expect(clientSecretValidation.minLength).toBe(10)
                expect(clientSecretValidation.message).toContain('clientSecret must be at least 10 characters')
            })
        })

        describe('scope validation', () => {
            test('has correct pattern and message', () => {
                const scopeValidation = oauth21Auth0Schema.validation.scope
                
                expect(scopeValidation.pattern).toBeInstanceOf(RegExp)
                expect(scopeValidation.message).toContain('valid OAuth scope characters')
            })

            test('pattern validates correct scope formats', () => {
                const pattern = oauth21Auth0Schema.validation.scope.pattern
                
                expect(pattern.test('openid profile email')).toBe(true)
                expect(pattern.test('read:users write:users')).toBe(true)
                expect(pattern.test('api-access')).toBe(true)
                expect(pattern.test('openid profile email read:users write:admin')).toBe(true)
                expect(pattern.test('scope_with_underscores')).toBe(true)
                expect(pattern.test('scope.with.dots')).toBe(true)
            })

            test('pattern rejects invalid scope formats', () => {
                const pattern = oauth21Auth0Schema.validation.scope.pattern
                
                expect(pattern.test('scope with @ symbol')).toBe(false)
                expect(pattern.test('scope with #')).toBe(false)
                expect(pattern.test('scope with % encoding')).toBe(false)
                expect(pattern.test('scope with $')).toBe(false)
                expect(pattern.test('')).toBe(false) // Empty string
            })
        })
    })

    describe('schema consistency', () => {
        test('all required field keys are unique', () => {
            const keys = oauth21Auth0Schema.requiredFields.map(field => field.key)
            const uniqueKeys = [...new Set(keys)]
            
            expect(keys).toHaveLength(uniqueKeys.length)
        })

        test('all optional field keys are unique', () => {
            const keys = oauth21Auth0Schema.optionalFields.map(field => field.key)
            const uniqueKeys = [...new Set(keys)]
            
            expect(keys).toHaveLength(uniqueKeys.length)
        })

        test('no overlap between required and optional field keys', () => {
            const requiredKeys = oauth21Auth0Schema.requiredFields.map(field => field.key)
            const optionalKeys = oauth21Auth0Schema.optionalFields.map(field => field.key)
            const intersection = requiredKeys.filter(key => optionalKeys.includes(key))
            
            expect(intersection).toHaveLength(0)
        })

        test('validation rules only apply to defined fields', () => {
            const allFieldKeys = [
                ...oauth21Auth0Schema.requiredFields.map(field => field.key),
                ...oauth21Auth0Schema.optionalFields.map(field => field.key)
            ]
            const validationKeys = Object.keys(oauth21Auth0Schema.validation)
            
            validationKeys.forEach(validationKey => {
                expect(allFieldKeys).toContain(validationKey)
            })
        })

        test('default values apply to defined fields', () => {
            const allFieldKeys = [
                ...oauth21Auth0Schema.requiredFields.map(field => field.key),
                ...oauth21Auth0Schema.optionalFields.map(field => field.key)
            ]
            const defaultKeys = Object.keys(oauth21Auth0Schema.defaults)
            
            defaultKeys.forEach(defaultKey => {
                expect(allFieldKeys).toContain(defaultKey)
            })
        })
    })
})