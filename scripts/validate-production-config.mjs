#!/usr/bin/env node

/**
 * Production Configuration Validator
 * 
 * Validates that all required environment variables and configurations
 * are properly set for production deployment.
 */

import { OAuthMiddleware } from '../src/index.mjs'

const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
}

const log = (message, color = 'reset') => {
    console.log(`${colors[color]}${message}${colors.reset}`)
}

const requiredEnvVars = [
    'NODE_ENV',
    'KEYCLOAK_URL',
    'PORT'
]

const validateEnvironmentVariables = () => {
    log('\n📋 Validating Environment Variables...', 'blue')
    let isValid = true
    
    for (const envVar of requiredEnvVars) {
        if (!process.env[envVar]) {
            log(`❌ Missing required environment variable: ${envVar}`, 'red')
            isValid = false
        } else {
            log(`✅ ${envVar}=${process.env[envVar]}`, 'green')
        }
    }
    
    // Check NODE_ENV is production
    if (process.env.NODE_ENV !== 'production') {
        log(`⚠️  NODE_ENV is "${process.env.NODE_ENV}", expected "production"`, 'yellow')
    }
    
    // Validate Keycloak URL format
    if (process.env.KEYCLOAK_URL) {
        try {
            const url = new URL(process.env.KEYCLOAK_URL)
            if (url.protocol !== 'https:') {
                log(`⚠️  Keycloak URL should use HTTPS in production: ${process.env.KEYCLOAK_URL}`, 'yellow')
            }
        } catch (error) {
            log(`❌ Invalid Keycloak URL format: ${process.env.KEYCLOAK_URL}`, 'red')
            isValid = false
        }
    }
    
    return isValid
}

const detectRealmConfigurations = () => {
    log('\n🔍 Detecting Realm Configurations...', 'blue')
    const realms = {}
    const envKeys = Object.keys(process.env)
    
    // Look for realm patterns
    const realmPrefixes = new Set()
    envKeys.forEach(key => {
        if (key.endsWith('_REALM')) {
            const prefix = key.replace('_REALM', '')
            realmPrefixes.add(prefix)
        }
    })
    
    for (const prefix of realmPrefixes) {
        const realmConfig = {
            realm: process.env[`${prefix}_REALM`],
            clientId: process.env[`${prefix}_CLIENT_ID`],
            clientSecret: process.env[`${prefix}_CLIENT_SECRET`],
            requiredScopes: process.env[`${prefix}_REQUIRED_SCOPES`],
            resourceUri: process.env[`${prefix}_RESOURCE_URI`]
        }
        
        log(`\n  Realm: ${prefix}`, 'blue')
        
        let isComplete = true
        for (const [key, value] of Object.entries(realmConfig)) {
            if (!value) {
                log(`    ❌ Missing ${key}`, 'red')
                isComplete = false
            } else {
                const displayValue = key === 'clientSecret' ? '***' : value
                log(`    ✅ ${key}: ${displayValue}`, 'green')
            }
        }
        
        if (isComplete) {
            const routePath = `/${prefix.toLowerCase().replace('_', '-')}`
            realms[routePath] = {
                keycloakUrl: process.env.KEYCLOAK_URL,
                realm: realmConfig.realm,
                clientId: realmConfig.clientId,
                clientSecret: realmConfig.clientSecret,
                requiredScopes: realmConfig.requiredScopes ? realmConfig.requiredScopes.split(',') : ['access'],
                resourceUri: realmConfig.resourceUri || `${process.env.BASE_URL || 'https://localhost'}${routePath}`
            }
        }
    }
    
    return realms
}

const validateMiddlewareConfiguration = async (realmConfigs) => {
    log('\n⚙️  Validating OAuth Middleware Configuration...', 'blue')
    
    if (Object.keys(realmConfigs).length === 0) {
        log('❌ No complete realm configurations found', 'red')
        return false
    }
    
    try {
        const middleware = await OAuthMiddleware.create({
            realmsByRoute: realmConfigs,
            silent: true // Suppress JWKS loading warnings in validation
        })
        
        const routes = middleware.getRoutes()
        const realms = middleware.getRealms()
        
        log(`✅ Middleware created successfully`, 'green')
        log(`   Routes: ${routes.join(', ')}`, 'green')
        log(`   Realms: ${realms.map(r => r.realm).join(', ')}`, 'green')
        
        // Test router creation
        const router = middleware.router()
        if (router && typeof router === 'function') {
            log(`✅ Express router created successfully`, 'green')
        } else {
            log(`❌ Failed to create Express router`, 'red')
            return false
        }
        
        return true
    } catch (error) {
        log(`❌ Middleware configuration failed: ${error.message}`, 'red')
        return false
    }
}

const validateSecurityConfiguration = () => {
    log('\n🔒 Validating Security Configuration...', 'blue')
    let securityScore = 0
    let totalChecks = 0
    
    const securityChecks = [
        {
            name: 'HTTPS enforcement',
            check: () => process.env.NODE_ENV === 'production',
            message: 'OAuth 2.1 enforces HTTPS in production'
        },
        {
            name: 'Client secrets not in logs',
            check: () => !process.env.DEBUG || !process.env.DEBUG.includes('oauth'),
            message: 'Avoid logging client secrets in debug mode'
        },
        {
            name: 'Secure session configuration',
            check: () => !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length >= 32,
            message: 'Use strong session secrets (32+ characters)'
        },
        {
            name: 'Rate limiting configured',
            check: () => process.env.RATE_LIMIT_ENABLED !== 'false',
            message: 'Enable rate limiting for production'
        }
    ]
    
    for (const { name, check, message } of securityChecks) {
        totalChecks++
        if (check()) {
            log(`✅ ${name}`, 'green')
            securityScore++
        } else {
            log(`⚠️  ${name}: ${message}`, 'yellow')
        }
    }
    
    const scorePercentage = (securityScore / totalChecks) * 100
    if (scorePercentage >= 75) {
        log(`\n🛡️  Security Score: ${scorePercentage.toFixed(0)}% (Good)`, 'green')
    } else {
        log(`\n⚠️  Security Score: ${scorePercentage.toFixed(0)}% (Needs Improvement)`, 'yellow')
    }
    
    return scorePercentage >= 50 // Minimum acceptable score
}

const generateSampleConfiguration = (realms) => {
    log('\n📄 Sample Production Configuration:', 'blue')
    
    console.log(`
# Base Configuration
NODE_ENV=production
PORT=3000
KEYCLOAK_URL=https://keycloak.yourdomain.com
BASE_URL=https://api.yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Performance
UV_THREADPOOL_SIZE=16
NODE_OPTIONS="--max-old-space-size=1024"
`)
    
    if (Object.keys(realms).length > 0) {
        console.log('# Realm Configurations')
        for (const [route, config] of Object.entries(realms)) {
            const prefix = route.substring(1).toUpperCase().replace('-', '_')
            console.log(`${prefix}_REALM=${config.realm}`)
            console.log(`${prefix}_CLIENT_ID=${config.clientId}`)
            console.log(`${prefix}_CLIENT_SECRET=your-secure-secret`)
            console.log(`${prefix}_REQUIRED_SCOPES=${config.requiredScopes.join(',')}`)
            console.log(`${prefix}_RESOURCE_URI=${config.resourceUri}`)
            console.log('')
        }
    } else {
        console.log(`
# Example Realm Configuration
API_REALM=production-api-realm
API_CLIENT_ID=prod-api-client
API_CLIENT_SECRET=your-secure-api-secret
API_REQUIRED_SCOPES=api:read,api:write
API_RESOURCE_URI=https://api.yourdomain.com/api
`)
    }
}

const main = async () => {
    log('🚀 OAuth Middleware Production Configuration Validator', 'blue')
    log('=' .repeat(60), 'blue')
    
    // Step 1: Validate environment variables
    const envValid = validateEnvironmentVariables()
    
    // Step 2: Detect realm configurations
    const realmConfigs = detectRealmConfigurations()
    
    // Step 3: Validate middleware can be created
    const middlewareValid = await validateMiddlewareConfiguration(realmConfigs)
    
    // Step 4: Security validation
    const securityValid = validateSecurityConfiguration()
    
    // Step 5: Generate sample config if needed
    if (Object.keys(realmConfigs).length === 0) {
        generateSampleConfiguration(realmConfigs)
    }
    
    // Summary
    log('\n📊 Validation Summary:', 'blue')
    log('=' .repeat(30), 'blue')
    
    const results = [
        { name: 'Environment Variables', status: envValid },
        { name: 'Realm Configurations', status: Object.keys(realmConfigs).length > 0 },
        { name: 'Middleware Creation', status: middlewareValid },
        { name: 'Security Configuration', status: securityValid }
    ]
    
    let allValid = true
    for (const { name, status } of results) {
        if (status) {
            log(`✅ ${name}`, 'green')
        } else {
            log(`❌ ${name}`, 'red')
            allValid = false
        }
    }
    
    if (allValid) {
        log('\n🎉 Production configuration is valid!', 'green')
        log('Your OAuth middleware is ready for production deployment.', 'green')
    } else {
        log('\n⚠️  Production configuration needs attention.', 'yellow')
        log('Please fix the issues above before deploying to production.', 'yellow')
    }
    
    process.exit(allValid ? 0 : 1)
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    await main()
}