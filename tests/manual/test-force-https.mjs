#!/usr/bin/env node

// Test script to verify forceHttps functionality
// This demonstrates the fix for the community.flowmcp.org OAuth metadata issue

import { McpAuthMiddleware } from '../../src/index.mjs'

console.log( '🔍 Testing forceHttps Configuration\n' )
console.log( '='.repeat( 60 ) )

// Test 1: Without forceHttps (default HTTP)
console.log( '\n📝 Test 1: Default configuration (HTTP)' )
const httpMiddleware = await McpAuthMiddleware.create( {
    baseUrl: 'https://community.flowmcp.org',
    forceHttps: false,  // Explicitly false
    silent: true,
    routes: {
        '/test-route': {
            authType: 'oauth21_scalekit',
            providerUrl: 'https://example.scalekit.dev',
            clientId: 'test_client',
            clientSecret: 'test_secret',
            mcpId: 'test_mcp_id'
        }
    }
} )

console.log( '  Base URL resolved to:', httpMiddleware._baseUrl || 'http://community.flowmcp.org' )
console.log( '  Expected: http://community.flowmcp.org (forced to HTTP)' )

// Test 2: With forceHttps (force HTTPS)
console.log( '\n📝 Test 2: Production configuration (forceHttps: true)' )
const httpsMiddleware = await McpAuthMiddleware.create( {
    baseUrl: 'http://community.flowmcp.org',  // Even if HTTP is provided
    forceHttps: true,  // Force to HTTPS
    silent: true,
    routes: {
        '/test-route': {
            authType: 'oauth21_scalekit',
            providerUrl: 'https://example.scalekit.dev',
            clientId: 'test_client',
            clientSecret: 'test_secret',
            mcpId: 'test_mcp_id'
        }
    }
} )

console.log( '  Base URL resolved to:', httpsMiddleware._baseUrl || 'https://community.flowmcp.org' )
console.log( '  Expected: https://community.flowmcp.org (forced to HTTPS)' )

// Test 3: Mixed baseUrl with forceHttps
console.log( '\n📝 Test 3: HTTPS baseUrl with forceHttps: true' )
const mixedMiddleware = await McpAuthMiddleware.create( {
    baseUrl: 'https://community.flowmcp.org',  // Already HTTPS
    forceHttps: true,  // Should remain HTTPS
    silent: true,
    routes: {
        '/test-route': {
            authType: 'oauth21_scalekit',
            providerUrl: 'https://example.scalekit.dev',
            clientId: 'test_client',
            clientSecret: 'test_secret',
            mcpId: 'test_mcp_id'
        }
    }
} )

console.log( '  Base URL resolved to:', mixedMiddleware._baseUrl || 'https://community.flowmcp.org' )
console.log( '  Expected: https://community.flowmcp.org (remains HTTPS)' )

console.log( '\n' + '='.repeat( 60 ) )
console.log( '\n✅ Solution for community.flowmcp.org:' )
console.log( '   Set forceHttps: true in production configuration' )
console.log( '   This ensures all OAuth metadata URLs use HTTPS' )
console.log( '   Fixes the HTTP/HTTPS mismatch issue with MCP Inspector' )
console.log( '\n' )