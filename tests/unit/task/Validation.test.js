import { Validation } from '../../../src/task/Validation.mjs'


describe( 'Validation', () => {

    describe( 'validationCreate', () => {

        test( 'returns success for valid staticBearer configuration', () => {
            const config = {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api', '/data' ]
                },
                silent: true,
                baseUrl: 'http://localhost:3000'
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'returns success for valid oauth21 scalekit configuration', () => {
            const config = {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                },
                silent: true,
                baseUrl: 'http://localhost:3000'
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'returns success for mixed staticBearer and oauth21 configuration', () => {
            const config = {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                },
                silent: true,
                baseUrl: 'http://localhost:3000'
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'validates unknown parameters', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                routes: { '/api': {} }, // Old API parameter
                silent: true,
                baseUrl: 'http://localhost:3000'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Unknown parameters: routes. Allowed: staticBearer, oauth21, silent, baseUrl, forceHttps' )
        } )


        test( 'validates create parameters object is required', () => {
            const result = Validation.validationCreate()

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Create parameters object is required' )
        } )


        test( 'validates create parameters object is not null', () => {
            const result = Validation.validationCreate( null )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Create parameters object is required' )
        } )


        test( 'validates silent field type', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                silent: 'not a boolean'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'silent: Must be a boolean' )
        } )


        test( 'validates baseUrl as string', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                baseUrl: 123
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'baseUrl: Must be a string' )
        } )


        test( 'validates baseUrl not empty', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                baseUrl: '   '
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'baseUrl: Cannot be empty' )
        } )


        test( 'validates baseUrl format', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                baseUrl: 'invalid-url'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages.some( msg => msg.includes( 'valid URL' ) ) ).toBe( true )
        } )


        test( 'validates baseUrl protocol', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                baseUrl: 'ftp://example.com'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'baseUrl: Must use http:// or https:// protocol' )
        } )


        test( 'validates baseUrl has no path', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                baseUrl: 'https://example.com/path'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'baseUrl: Must not contain a path (use protocol://host:port format)' )
        } )


        test( 'validates forceHttps as boolean', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                forceHttps: 'not a boolean'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'forceHttps: Must be a boolean' )
        } )


        test( 'allows unprotected server with no auth types', () => {
            const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                silent: true,
                baseUrl: 'http://localhost:3000'
            } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        describe( 'staticBearer validation', () => {

            test( 'validates staticBearer as object', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: 'not an object'
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer: Must be an object' )
            } )


            test( 'allows staticBearer to be null for unprotected server', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: null
                } )

                expect( result.status ).toBe( true )
                expect( result.messages ).toHaveLength( 0 )
            } )


            test( 'validates staticBearer tokenSecret is required', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        attachedRoutes: [ '/api' ]
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.tokenSecret: Missing value' )
            } )


            test( 'validates staticBearer tokenSecret as string', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 123,
                        attachedRoutes: [ '/api' ]
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.tokenSecret: Must be a string' )
            } )


            test( 'validates staticBearer tokenSecret not empty', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: '   ',
                        attachedRoutes: [ '/api' ]
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.tokenSecret: Cannot be empty' )
            } )


            test( 'validates staticBearer attachedRoutes is required', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456'
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.attachedRoutes: Missing value' )
            } )


            test( 'validates staticBearer attachedRoutes as array', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456',
                        attachedRoutes: 'not an array'
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.attachedRoutes: Must be an array' )
            } )


            test( 'validates staticBearer attachedRoutes not empty', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456',
                        attachedRoutes: []
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.attachedRoutes: Cannot be empty array' )
            } )


            test( 'validates staticBearer route paths format', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456',
                        attachedRoutes: [ 'invalid-route', '/valid' ]
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'staticBearer.attachedRoutes[0]: Must start with /' )
            } )



        } )


        describe( 'oauth21 validation', () => {

            test( 'validates oauth21 as object', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: 'not an object'
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'oauth21: Must be an object' )
            } )


            test( 'allows oauth21 to be null for unprotected server', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: null
                } )

                expect( result.status ).toBe( true )
                expect( result.messages ).toHaveLength( 0 )
            } )


            test( 'validates oauth21 authType is required', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        attachedRoutes: [ '/oauth' ],
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'oauth21.authType: Missing value' )
            } )


            test( 'validates oauth21 authType is oauth21_scalekit', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        authType: 'oauth21_auth0', // Not supported anymore
                        attachedRoutes: [ '/oauth' ],
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'oauth21.authType: Unsupported value "oauth21_auth0". Only "oauth21_scalekit" is supported' )
            } )


            test( 'validates oauth21 scalekit required fields', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        attachedRoutes: [ '/oauth' ],
                        options: {
                            providerUrl: 'https://auth.scalekit.com'
                            // Missing: mcpId, clientId, clientSecret, resource, scope
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages.some( msg => msg.includes( 'missing required fields' ) ) ).toBe( true )
            } )


            test( 'validates oauth21 providerUrl format', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        attachedRoutes: [ '/oauth' ],
                        options: {
                            providerUrl: 'invalid-url',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages.some( msg => msg.includes( 'valid URL' ) ) ).toBe( true )
            } )


            test( 'validates oauth21 mcpId format', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        attachedRoutes: [ '/oauth' ],
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'invalid_format', // Should start with 'res_'
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages.some( msg => msg.includes( "requires mcpId to start with 'res_'" ) ) ).toBe( true )
            } )


            test( 'validates oauth21 attachedRoutes is required', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'oauth21.attachedRoutes: Missing value' )
            } )

        } )


        describe( 'route conflicts validation', () => {

            test( 'detects route conflicts between staticBearer and oauth21', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456',
                        attachedRoutes: [ '/api', '/data' ]
                    },
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        attachedRoutes: [ '/oauth', '/api' ], // Conflict with /api
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( false )
                expect( result.messages ).toContain( 'Route conflict: Routes cannot be in both staticBearer and oauth21 attachedRoutes: /api' )
            } )


            test( 'allows no route conflicts', () => {
                const result = Validation.validationCreate( { baseUrl: 'http://localhost:3000',
                    staticBearer: {
                        tokenSecret: 'test-token-123456',
                        attachedRoutes: [ '/api', '/data' ]
                    },
                    oauth21: {
                        authType: 'oauth21_scalekit',
                        attachedRoutes: [ '/oauth', '/auth' ],
                        options: {
                            providerUrl: 'https://auth.scalekit.com',
                            mcpId: 'res_test123',
                            clientId: 'test-client-id',
                            clientSecret: 'test-client-secret',
                            resource: 'mcp:tools:*',
                            scope: 'mcp:tools:* mcp:resources:read'
                        }
                    }
                } )

                expect( result.status ).toBe( true )
                expect( result.messages ).toHaveLength( 0 )
            } )

        } )

    } )

} )