#!/usr/bin/env node

/**
 * Health Check Script
 * 
 * Validates that the OAuth middleware is running and responding correctly
 * by checking the OAuth Authorization Server metadata endpoint.
 */

import fetch from 'node-fetch'

const healthCheck = async () => {
    const port = process.env.PORT || 3000
    const timeout = parseInt(process.env.HEALTH_CHECK_TIMEOUT || '5000')
    
    try {
        // Check OAuth Authorization Server metadata endpoint
        const response = await fetch(`http://localhost:${port}/.well-known/oauth-authorization-server`, {
            timeout,
            headers: {
                'User-Agent': 'OAuth-Middleware-HealthCheck/1.0'
            }
        })
        
        if (!response.ok) {
            console.error(`Health check failed: HTTP ${response.status}`)
            process.exit(1)
        }
        
        const metadata = await response.json()
        
        // Validate that the response contains expected OAuth metadata
        if (!metadata.authorization_servers || !metadata.jwks_uri) {
            console.error('Health check failed: Invalid OAuth metadata response')
            process.exit(1)
        }
        
        // Optional: Check JWKS endpoint as well
        if (process.env.HEALTH_CHECK_JWKS === 'true') {
            const jwksResponse = await fetch(`http://localhost:${port}/.well-known/jwks.json`, {
                timeout: timeout / 2
            })
            
            if (!jwksResponse.ok) {
                console.error(`JWKS health check failed: HTTP ${jwksResponse.status}`)
                process.exit(1)
            }
        }
        
        console.log('Health check passed')
        process.exit(0)
        
    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.error('Health check failed: Service not responding')
        } else if (error.name === 'AbortError') {
            console.error('Health check failed: Request timeout')
        } else {
            console.error(`Health check failed: ${error.message}`)
        }
        process.exit(1)
    }
}

await healthCheck()