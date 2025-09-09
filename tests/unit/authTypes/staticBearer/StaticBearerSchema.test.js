import { staticBearerSchema } from '../../../../src/authTypes/staticBearer/StaticBearerSchema.mjs'

describe('StaticBearerSchema', () => {
    describe('schema structure', () => {
        test('has correct basic metadata', () => {
            expect(staticBearerSchema.name).toBe('Static Bearer Token')
            expect(staticBearerSchema.description).toBe('Simple static bearer token authentication')
            expect(staticBearerSchema.authType).toBe('staticBearer')
        })

        test('has all required structure properties', () => {
            expect(staticBearerSchema).toHaveProperty('name')
            expect(staticBearerSchema).toHaveProperty('description')
            expect(staticBearerSchema).toHaveProperty('authType')
            expect(staticBearerSchema).toHaveProperty('requiredFields')
            expect(staticBearerSchema).toHaveProperty('optionalFields')
            expect(staticBearerSchema).toHaveProperty('defaults')
            expect(staticBearerSchema).toHaveProperty('validation')
        })

        test('has arrays for field definitions', () => {
            expect(Array.isArray(staticBearerSchema.requiredFields)).toBe(true)
            expect(Array.isArray(staticBearerSchema.optionalFields)).toBe(true)
        })

        test('has objects for defaults and validation', () => {
            expect(typeof staticBearerSchema.defaults).toBe('object')
            expect(typeof staticBearerSchema.validation).toBe('object')
        })
    })

    describe('required fields', () => {
        test('has correct number of required fields', () => {
            expect(staticBearerSchema.requiredFields).toHaveLength(1)
        })

        test('includes token field', () => {
            const tokenField = staticBearerSchema.requiredFields.find(field => field.key === 'token')
            
            expect(tokenField).toBeDefined()
            expect(tokenField.type).toBe('string')
            expect(tokenField.description).toContain('static bearer token')
            expect(tokenField.description).toContain('without Bearer prefix')
            expect(tokenField.example).toBe('abc123def456ghi789')
        })

        test('all required fields have necessary properties', () => {
            staticBearerSchema.requiredFields.forEach(field => {
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
        test('has no optional fields', () => {
            expect(staticBearerSchema.optionalFields).toHaveLength(0)
        })
    })

    describe('defaults', () => {
        test('has empty defaults object', () => {
            expect(staticBearerSchema.defaults).toEqual({})
        })
    })

    describe('validation rules', () => {
        test('has validation rules for token field', () => {
            expect(staticBearerSchema.validation).toHaveProperty('token')
        })

        describe('token validation', () => {
            test('has correct minLength and message', () => {
                const tokenValidation = staticBearerSchema.validation.token
                
                expect(tokenValidation.minLength).toBe(8)
                expect(tokenValidation.message).toContain('not start with "Bearer"')
                expect(tokenValidation.message).toContain('at least 8 characters')
            })

            test('pattern rejects Bearer prefix', () => {
                const pattern = staticBearerSchema.validation.token.pattern
                
                expect(pattern.test('Bearer abc123')).toBe(false)
                expect(pattern.test('bearer abc123')).toBe(false)
                expect(pattern.test('BEARER abc123')).toBe(false)
            })

            test('pattern accepts valid tokens', () => {
                const pattern = staticBearerSchema.validation.token.pattern
                
                expect(pattern.test('abc123def456')).toBe(true)
                expect(pattern.test('token-with-dashes')).toBe(true)
                expect(pattern.test('Token123')).toBe(true)
                expect(pattern.test('very_long_token_string_here')).toBe(true)
            })
        })
    })

    describe('schema consistency', () => {
        test('all required field keys are unique', () => {
            const keys = staticBearerSchema.requiredFields.map(field => field.key)
            const uniqueKeys = [...new Set(keys)]
            
            expect(keys).toHaveLength(uniqueKeys.length)
        })

        test('no overlap between required and optional field keys', () => {
            const requiredKeys = staticBearerSchema.requiredFields.map(field => field.key)
            const optionalKeys = staticBearerSchema.optionalFields.map(field => field.key)
            const intersection = requiredKeys.filter(key => optionalKeys.includes(key))
            
            expect(intersection).toHaveLength(0)
        })

        test('validation rules only apply to defined fields', () => {
            const allFieldKeys = [
                ...staticBearerSchema.requiredFields.map(field => field.key),
                ...staticBearerSchema.optionalFields.map(field => field.key)
            ]
            const validationKeys = Object.keys(staticBearerSchema.validation)
            
            validationKeys.forEach(validationKey => {
                expect(allFieldKeys).toContain(validationKey)
            })
        })

        test('default values apply to defined fields', () => {
            const allFieldKeys = [
                ...staticBearerSchema.requiredFields.map(field => field.key),
                ...staticBearerSchema.optionalFields.map(field => field.key)
            ]
            const defaultKeys = Object.keys(staticBearerSchema.defaults)
            
            defaultKeys.forEach(defaultKey => {
                expect(allFieldKeys).toContain(defaultKey)
            })
        })
    })
})