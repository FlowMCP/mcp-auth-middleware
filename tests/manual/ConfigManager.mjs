import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { SchemaImporter } from 'schemaImporter'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename )


class ConfigManager {
    static async getConfig( { authTypKey } ) {
        const config = {
            'silent': false,
            'envPath': '../../../.auth.env',
            'route': '/scalekit-route',
            'baseUrl': 'http://localhost',
            'port': 3000,
            'protocol': '/streamable',
            authTypKey,
            'forceHttps': false,
            'routePath': null,
            'fullUrl': null,
            'browserTimeout': 90000,
        }

        const { route, protocol } = config
        config['routePath'] = `${route}${protocol}`

        const { envPath, baseUrl, port, routePath } = config
        config['fullUrl'] = `${baseUrl}:${port}${routePath}`

        const { authTypValue } = await ConfigManager
            .getAuthTyp( { envPath, baseUrl, port, routePath, authTypKey } )

        return { config, authTypValue }
    }


    static async getAuthTyp( { envPath, baseUrl, port, routePath, authTypKey } ) {
        const envParams = this.#getServerParams( {
            'path': path.resolve( __dirname, envPath ),
            'requiredServerParams': [
                'FIRST_ROUTE_AUTH0_DOMAIN',
                'FIRST_ROUTE_AUTH0_CLIENT_ID',
                'FIRST_ROUTE_AUTH0_CLIENT_SECRET',
                'THIRD_ROUTE_BEARER_TOKEN',
                'SCALEKIT_ENVIRONMENT_URL',
                'SCALEKIT_CLIENT_ID',
                'SCALEKIT_CLIENT_SECRET',
                'SCALEKIT_MCP_ID',
                'SCALEKIT_ORGANIZATION_ID'
            ]
        } )

        const {
            FIRST_ROUTE_AUTH0_DOMAIN: firstRouteAuth0Domain,
            FIRST_ROUTE_AUTH0_CLIENT_ID: firstRouteAuth0ClientId,
            FIRST_ROUTE_AUTH0_CLIENT_SECRET: firstRouteAuth0ClientSecret,
            THIRD_ROUTE_BEARER_TOKEN: thirdRouteBearerToken,
            SCALEKIT_ENVIRONMENT_URL: scalekitEnvironmentUrl,
            SCALEKIT_CLIENT_ID: scalekitClientId,
            SCALEKIT_CLIENT_SECRET: scalekitClientSecret,
            SCALEKIT_MCP_ID: scalekitMcpId,
            SCALEKIT_ORGANIZATION_ID: scalekitOrganizationId
        } = envParams

        const authTypes = {
            'staticBearer': {
                'enabled': true,
                'authType': 'staticBearer',
                'token': thirdRouteBearerToken
            },
            'oauth21_auth0': {
                'enabled': true,
                'authType': 'oauth21_auth0',
                'providerName': 'auth0',
                'providerUrl': `https://${firstRouteAuth0Domain}`,
                'realm': 'first-route-realm',
                'clientId': firstRouteAuth0ClientId,
                'clientSecret': firstRouteAuth0ClientSecret,
                'scope': 'openid profile email',
                'audience': `${baseUrl}${port}/${routePath}`,
                'authFlow': 'authorization_code',
                'requiredScopes': [ 'openid', 'profile', 'email' ],
                'requiredRoles': [ 'user' ],
                'resourceUri': `${baseUrl}:${port}${routePath}`,
                'forceHttps': true
            },
            'oauth21_scalekit': {
                'enabled': true,
                'authType': 'oauth21_scalekit',
                'providerUrl': scalekitEnvironmentUrl,
                'mcpId': scalekitMcpId,
                'clientId': scalekitClientId,
                'clientSecret': scalekitClientSecret,
                'organizationId': scalekitOrganizationId,
                'resource': scalekitClientId,
                'resourceDocumentation': `${baseUrl}${port}/${routePath}/docs`,
                'scope': 'tools:read',
                'authFlow': 'authorization_code',
                'forceHttps': false
            }
        }

        const authTypValue = authTypes[ authTypKey ]
        return { authTypValue }
    }


    static #getServerParams( { path, requiredServerParams } ) {
        const selection = requiredServerParams
            .map( ( serverParam ) => [ serverParam, serverParam ] )

        const result = fs
            .readFileSync( path, 'utf-8' )
            .split( "\n" )
            .map( line => line.split( '=' ) )
            .reduce( ( acc, [ k, v ] ) => {
                const find = selection.find( ( [ _, value ] ) => value === k )
                if( find ) {  acc[ find[ 0 ] ] = v  }
                return acc
            }, {} )

        selection
            .forEach( ( row ) => {
                const [ key, _ ] = row
                if( !result[ key ]  ) { console.log( `Missing ${key} in .env file` ) }
                return true
            } )

        return result
    }
}


export { ConfigManager }
