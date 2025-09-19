import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { SchemaImporter } from 'schemaImporter'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename )


class ConfigManager {
    static async getConfig( { authTypKey, baseUrl='http://localhost', forceHttps=false, port=3000 } ) {
        const config = {
            'silent': false,
            'envPath': '../../../.auth.env',
            'route': '/scalekit-route',
            baseUrl,
            port,
            'protocol': '/sse',
            authTypKey,
            forceHttps,
            'routePath': null,
            'fullUrl': null,
            'browserTimeout': 90000,
        }

        const { route, protocol } = config
        config['routePath'] = `${route}${protocol}`

        const { envPath, baseUrl: configBaseUrl, port: configPort, routePath } = config
        if( configPort === null ) {
            config['fullUrl'] = `${configBaseUrl}${routePath}`
        } else {
            config['fullUrl'] = `${configBaseUrl}:${configPort}${routePath}`
        }

        const { authTypValue } = await ConfigManager
            .getAuthTyp( { envPath, baseUrl: configBaseUrl, port: configPort, routePath, authTypKey } )

        return { config, authTypValue }
    }


    static async getRemoteConfig( { baseUrl, port, routePath } ) {
        const remoteConfig = {
            'silent': false,
            'envPath': '../../../.auth.env',
            'authTypKey': 'oauth21_scalekit',
            'forceHttps': false,
            'browserTimeout': 90000,
            baseUrl,
            port,
            routePath
        }

        const { authTypValue } = await ConfigManager
            .getAuthTyp( { envPath: remoteConfig.envPath, baseUrl, port, routePath, authTypKey: remoteConfig.authTypKey } )

        return { config: remoteConfig, authTypValue }
    }


    static async getAuthTyp( { envPath, baseUrl, port, routePath, authTypKey } ) {
        const envParams = this.#getServerParams( {
            'path': path.resolve( __dirname, envPath ),
            'requiredServerParams': [
                'THIRD_ROUTE_BEARER_TOKEN',
                'SCALEKIT_ENVIRONMENT_URL',
                'SCALEKIT_CLIENT_ID',
                'SCALEKIT_CLIENT_SECRET',
                'SCALEKIT_MCP_ID',
                'SCALEKIT_ORGANIZATION_ID'
            ]
        } )

        const {
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
