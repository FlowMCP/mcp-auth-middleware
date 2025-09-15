import { OAuth21ScalekitProvider } from '../../../../src/authTypes/oauth21_scalekit/OAuth21ScalekitProvider.mjs'

describe( 'OAuth21ScalekitProvider - Custom Domain Support', () => {

    test( 'accepts ScaleKit hosted domain', () => {
        const config = {
            providerUrl: 'https://flowmcp-afaeuirdaafqi.scalekit.dev',
            mcpId: 'res_90153735103187214',
            clientId: 'skc_90153504634571524',
            clientSecret: 'test_secret',
            resource: 'http://localhost:3001/scalekit-route',
            scope: 'openid profile mcp:tools'
        }

        const result = OAuth21ScalekitProvider.validateOAuth21ScalekitConfig( { config } )

        expect( result.status ).toBe( true )
        expect( result.messages ).toEqual( [] )
    } )

    test( 'accepts custom domain (company.com)', () => {
        const config = {
            providerUrl: 'https://auth.company.com',
            mcpId: 'res_90153735103187214',
            clientId: 'skc_90153504634571524',
            clientSecret: 'test_secret',
            resource: 'http://localhost:3001/scalekit-route',
            scope: 'openid profile mcp:tools'
        }

        const result = OAuth21ScalekitProvider.validateOAuth21ScalekitConfig( { config } )

        expect( result.status ).toBe( true )
        expect( result.messages ).toEqual( [] )
    } )

    test( 'accepts custom domain (oauth.enterprise.org)', () => {
        const config = {
            providerUrl: 'https://oauth.enterprise.org',
            mcpId: 'res_90153735103187214',
            clientId: 'skc_90153504634571524',
            clientSecret: 'test_secret',
            resource: 'http://localhost:3001/scalekit-route',
            scope: 'openid profile mcp:tools'
        }

        const result = OAuth21ScalekitProvider.validateOAuth21ScalekitConfig( { config } )

        expect( result.status ).toBe( true )
        expect( result.messages ).toEqual( [] )
    } )

    test( 'rejects HTTP domain (HTTPS required)', () => {
        const config = {
            providerUrl: 'http://insecure.company.com',
            mcpId: 'res_90153735103187214',
            clientId: 'skc_90153504634571524',
            clientSecret: 'test_secret',
            resource: 'http://localhost:3001/scalekit-route',
            scope: 'openid profile mcp:tools'
        }

        const result = OAuth21ScalekitProvider.validateOAuth21ScalekitConfig( { config } )

        expect( result.status ).toBe( false )
        expect( result.messages ).toContainEqual(
            expect.stringContaining( 'OAuth21Scalekit config validation failed' )
        )
    } )

    test( 'rejects invalid domain format', () => {
        const config = {
            providerUrl: 'https://invalid',
            mcpId: 'res_90153735103187214',
            clientId: 'skc_90153504634571524',
            clientSecret: 'test_secret',
            resource: 'http://localhost:3001/scalekit-route',
            scope: 'openid profile mcp:tools'
        }

        const result = OAuth21ScalekitProvider.validateOAuth21ScalekitConfig( { config } )

        expect( result.status ).toBe( false )
        expect( result.messages ).toContainEqual(
            expect.stringContaining( 'OAuth21Scalekit config validation failed' )
        )
    } )

} )