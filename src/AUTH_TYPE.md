# AuthType System Documentation

## 🎯 Overview

The OAuth Middleware uses an extensible **AuthType system** where each authentication method is implemented as a separate, self-contained module. This allows for easy addition of new authentication providers and methods.

## 📁 Architecture

```
src/
├── core/                       # Core AuthType system
│   ├── AuthTypeRegistry.mjs    # Registry of all supported AuthTypes
│   ├── AuthTypeValidator.mjs   # Schema-based validation
│   └── AuthTypeFactory.mjs     # Factory for creating AuthType handlers
├── authTypes/                  # AuthType implementations
│   └── oauth21_auth0/         # OAuth 2.1 with Auth0 provider
│       ├── OAuth21Auth0Schema.mjs        # Schema definition
│       ├── OAuth21Auth0Provider.mjs      # Provider implementation
│       ├── OAuth21Auth0TokenValidator.mjs # Token validation
│       └── OAuth21Auth0FlowHandler.mjs   # OAuth flow handling
└── helpers/                    # Generic helpers (reused by all AuthTypes)
    ├── Logger.mjs
    ├── PKCEGenerator.mjs
    └── ...
```

## 🔧 Current AuthTypes

### `oauth21_auth0` - OAuth 2.1 with Auth0

**Configuration:**
```javascript
{
    authType: 'oauth21_auth0',
    providerUrl: 'https://tenant.auth0.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    scope: 'openid profile email',
    audience: 'https://your-api.example.com'
}
```

**Features:**
- ✅ OAuth 2.1 compliance
- ✅ PKCE (Proof Key for Code Exchange)
- ✅ JWT token validation
- ✅ Audience binding (RFC 8707)
- ✅ Scope-based authorization
- ✅ Automatic endpoint discovery

## 🚀 Adding New AuthTypes

### Step 1: Create AuthType Directory
```bash
mkdir src/authTypes/your_new_authtype/
```

### Step 2: Create Schema Definition
Create `src/authTypes/your_new_authtype/YourNewAuthtypeSchema.mjs`:

```javascript
const yourNewAuthtypeSchema = {
    requiredFields: [
        { key: 'field1', type: 'string', description: 'Required field description' },
        { key: 'field2', type: 'string', description: 'Another required field' }
    ],
    optionalFields: [
        { key: 'optionalField', type: 'boolean', description: 'Optional field description' }
    ],
    defaults: {
        optionalField: true
    }
}

export { yourNewAuthtypeSchema }
```

### Step 3: Create Provider
Create `src/authTypes/your_new_authtype/YourNewAuthtypeProvider.mjs`:

```javascript
import { Logger } from '../../helpers/Logger.mjs'

class YourNewAuthtypeProvider {
    #config
    #silent

    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }

    generateEndpoints( { config } ) {
        // Return endpoints object with authorizationUrl, tokenUrl, etc.
        return {
            endpoints: {
                authorizationUrl: `${config.providerUrl}/auth`,
                tokenUrl: `${config.providerUrl}/token`,
                jwksUrl: `${config.providerUrl}/.well-known/jwks.json`
            }
        }
    }

    generateConfiguration( { config } ) {
        // Return normalized configuration
        return {
            authType: 'your_new_authtype',
            ...config
        }
    }
}

export { YourNewAuthtypeProvider }
```

### Step 4: Create Token Validator
Create `src/authTypes/your_new_authtype/YourNewAuthtypeTokenValidator.mjs`:

```javascript
class YourNewAuthtypeTokenValidator {
    #config
    #silent

    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }

    async validateToken( { token } ) {
        // Implement token validation logic
        return {
            isValid: true,
            decoded: { /* decoded token */ },
            error: null
        }
    }
}

export { YourNewAuthtypeTokenValidator }
```

### Step 5: Create Flow Handler
Create `src/authTypes/your_new_authtype/YourNewAuthtypeFlowHandler.mjs`:

```javascript
class YourNewAuthtypeFlowHandler {
    #config
    #silent

    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }

    initiateAuthFlow( { scopes, redirectUri } ) {
        // Return authorization URL and state
        return {
            authorizationUrl: 'https://example.com/auth',
            state: 'generated-state'
        }
    }

    async handleCallback( { code, state } ) {
        // Handle OAuth callback
        return {
            success: true,
            tokens: { /* token response */ }
        }
    }
}

export { YourNewAuthtypeFlowHandler }
```

### Step 6: Register AuthType
Update `src/core/AuthTypeRegistry.mjs`:

```javascript
this.#authTypes.set( 'your_new_authtype', {
    name: 'Your New AuthType',
    description: 'Description of your new authentication type',
    schemaPath: '../authTypes/your_new_authtype/YourNewAuthtypeSchema.mjs',
    providerPath: '../authTypes/your_new_authtype/YourNewAuthtypeProvider.mjs',
    tokenValidatorPath: '../authTypes/your_new_authtype/YourNewAuthtypeTokenValidator.mjs',
    flowHandlerPath: '../authTypes/your_new_authtype/YourNewAuthtypeFlowHandler.mjs'
} )
```

### Step 7: Add Factory Support
Update `src/core/AuthTypeFactory.mjs`:

```javascript
static async #instantiateHandler( { authType, config, handlerConfig, silent } ) {
    if( authType === 'oauth21_auth0' ) {
        return await AuthTypeFactory.#createOAuth21Auth0Handler( { config, handlerConfig, silent } )
    } else if( authType === 'your_new_authtype' ) {
        return await AuthTypeFactory.#createYourNewAuthtypeHandler( { config, handlerConfig, silent } )
    }

    throw new Error( `No factory implementation found for authType: ${authType}` )
}

static async #createYourNewAuthtypeHandler( { config, handlerConfig, silent } ) {
    try {
        const { YourNewAuthtypeProvider } = await import( handlerConfig.providerPath )
        const { YourNewAuthtypeTokenValidator } = await import( handlerConfig.tokenValidatorPath )
        const { YourNewAuthtypeFlowHandler } = await import( handlerConfig.flowHandlerPath )

        const provider = new YourNewAuthtypeProvider( { config, silent } )
        const tokenValidator = new YourNewAuthtypeTokenValidator( { config, silent } )
        const flowHandler = new YourNewAuthtypeFlowHandler( { config, silent } )

        return {
            authType: 'your_new_authtype',
            provider,
            tokenValidator,
            flowHandler,
            config
        }
    } catch( error ) {
        throw new Error( `Failed to create YourNewAuthtype handler: ${error.message}` )
    }
}
```

## 🧪 Testing New AuthTypes

### Create Test Template
Create `tests/unit/authTypes/your_new_authtype/`:

```javascript
// YourNewAuthtypeProvider.test.js
import { YourNewAuthtypeProvider } from '../../../../src/authTypes/your_new_authtype/YourNewAuthtypeProvider.mjs'

describe( 'YourNewAuthtypeProvider', () => {
    test( 'creates provider with valid config', () => {
        const config = { /* valid config */ }
        const provider = new YourNewAuthtypeProvider( { config } )
        expect( provider ).toBeDefined()
    } )

    test( 'generates correct endpoints', () => {
        const provider = new YourNewAuthtypeProvider( { config: testConfig } )
        const { endpoints } = provider.generateEndpoints( { config: testConfig } )
        
        expect( endpoints.authorizationUrl ).toBeDefined()
        expect( endpoints.tokenUrl ).toBeDefined()
    } )
} )
```

## 📝 Schema Validation

Each AuthType must define a schema with:

- **requiredFields**: Array of required configuration fields
- **optionalFields**: Array of optional configuration fields  
- **defaults**: Default values for optional fields
- **validation**: Custom validation rules (optional)

**Example:**
```javascript
const schema = {
    requiredFields: [
        { key: 'providerUrl', type: 'string', description: 'Auth provider URL' },
        { key: 'clientId', type: 'string', description: 'OAuth client ID' }
    ],
    optionalFields: [
        { key: 'timeout', type: 'number', description: 'Request timeout in ms' }
    ],
    defaults: {
        timeout: 30000
    }
}
```

## 🔮 Future AuthTypes

Planned AuthType implementations:

- `oauth21_azure` - OAuth 2.1 with Azure Active Directory
- `oauth21_google` - OAuth 2.1 with Google  
- `oauth21_okta` - OAuth 2.1 with Okta
- `api_key` - API Key authentication
- `jwt_bearer` - JWT Bearer token authentication
- `basic_auth` - HTTP Basic Authentication

## 🛠️ Development Guidelines

1. **Naming Convention**: Use `{protocol}_{provider}` format (e.g., `oauth21_auth0`)
2. **Class Naming**: Use PascalCase with AuthType prefix (e.g., `OAuth21Auth0Provider`)
3. **File Structure**: Keep each AuthType in its own directory
4. **Dependencies**: Minimize external dependencies, reuse helpers
5. **Testing**: Provide comprehensive test coverage
6. **Documentation**: Document all configuration fields and methods
7. **Error Handling**: Provide clear, actionable error messages

## 🤝 Contributing

When contributing new AuthTypes:

1. Follow the step-by-step guide above
2. Include comprehensive tests
3. Update this documentation
4. Provide configuration examples
5. Test with real-world scenarios

---

**The AuthType system makes the OAuth Middleware infinitely extensible while maintaining clean separation of concerns.**