import { SchemaImporter } from 'schemaImporter'
import { TestUtils } from '../helpers/utils.mjs'


const envParams = TestUtils.getEnvParams( {
    'envPath': './../../../.auth.env',
    'selection': [
        [ 'firstRouteAuth0Domain',        'FIRST_ROUTE_AUTH0_DOMAIN'         ],
        [ 'firstRouteAuth0ClientId',      'FIRST_ROUTE_AUTH0_CLIENT_ID'      ],
        [ 'firstRouteAuth0ClientSecret',  'FIRST_ROUTE_AUTH0_CLIENT_SECRET'  ],
        [ 'secondRouteAuth0Domain',       'SECOND_ROUTE_AUTH0_DOMAIN'        ],
        [ 'secondRouteAuth0ClientId',     'SECOND_ROUTE_AUTH0_CLIENT_ID'     ],
        [ 'secondRouteAuth0ClientSecret', 'SECOND_ROUTE_AUTH0_CLIENT_SECRET' ],
        [ 'thirdRouteBearerToken',        'THIRD_ROUTE_BEARER_TOKEN'         ]
    ]
} )

const { 
    firstRouteAuth0Domain, 
    firstRouteAuth0ClientId, 
    firstRouteAuth0ClientSecret,
    secondRouteAuth0Domain, 
    secondRouteAuth0ClientId, 
    secondRouteAuth0ClientSecret,
    thirdRouteBearerToken
} = envParams

const config = {
    'silent': false, // Set to true to disable OAuth route output  
    'envPath': './../../.env',
    'rootUrl': 'http://localhost', // optional
    'port': 3000, // optional
    'routeConfigs': [
        {
            'authType': 'oauth21_auth0',
            'routePath': '/first-route',
            'name': 'First Auth0 Route',
            'description': 'Testing first Auth0 client configuration with ERC20 schemas',
            'bearerIsPublic': false,
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 0 ) // nur das erste Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'authType': 'oauth21_auth0',
                'providerName': 'auth0', // EXPLICIT PROVIDER SPECIFICATION
                'providerUrl': `https://${firstRouteAuth0Domain}`,
                'realm': 'first-route-realm', // Auth0 pseudo-realm für erste Route
                'clientId': firstRouteAuth0ClientId || 'your-first-route-client-id',
                'clientSecret': firstRouteAuth0ClientSecret || 'your-first-route-client-secret',
                'scope': 'openid profile email',
                'audience': 'http://localhost:3000/first-route',
                'resourceUri': null,
                'forceHttps': false
            }
        },
/*
        {
            'authType': 'oauth21_auth0',
            'routePath': '/second-route',
            'name': 'Second Auth0 Route',
            'description': 'Testing second Auth0 client configuration with different schemas',
            'bearerIsPublic': false,
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 1 ) // nur das zweite Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'providerName': 'auth0', // EXPLICIT PROVIDER SPECIFICATION
                'providerUrl': `https://${secondRouteAuth0Domain}`,
                'realm': 'second-route-realm', // Auth0 pseudo-realm für zweite Route
                'clientId': secondRouteAuth0ClientId || 'your-second-route-client-id',
                'clientSecret': secondRouteAuth0ClientSecret || 'your-second-route-client-secret',
                'scope': 'openid profile email',
                'audience': 'http://localhost:3000/second-route',
                'resourceUri': null,
                'forceHttps': false
            }
        },
*/
/*
        {
            'routePath': '/third-route',
            'name': 'Third Route',
            'description': 'A third route without authentication',
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 2 ) // nur das dritte Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'authType': 'staticBearer',
                'token': thirdRouteBearerToken
            }
        },
*/
    ]
}

const { rootUrl, port } = config
config['routeConfigs'] = config['routeConfigs']
    .map( ( route ) => {
        const { auth: { authType } } = route
        const { routePath } = route
        if( authType === 'oauth21_auth0' ) {
            route['auth']['resourceUri'] = `${rootUrl}:${port}${routePath}`
        }
        return route
    } )

export { config }