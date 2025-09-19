import { spawn } from 'child_process'

import { StreamableTester } from './testers/StreamableTester.mjs'
import { BearerTester } from './testers/BearerTester.mjs'
import { OAuthTester } from './testers/OAuthTester.mjs'
import { TestValidation } from './helpers/TestValidation.mjs'


class OAuthMiddlewareTester {
    static #runningScripts = new Set()


    static getRunningScripts() {
        return this.#runningScripts
    }


    static async testStreamableRoute( { baseUrl, routePath, timeout = 30000, expectedStatus = 200 } ) {
        const { status, messages } = TestValidation.validationTestStreamableRoute( { baseUrl, routePath } )
        if( !status ) {
            TestValidation.error( { messages } )
        }

        const testResult = await StreamableTester.runTest( {
            baseUrl,
            routePath,
            timeout,
            expectedStatus
        } )

        return testResult
    }


    static async testBearerStreamable( { baseUrl, routePath, bearerToken, timeout = 30000, testUnauthorized = true, expectedUnauthorizedStatus = 401 } ) {
        const { status, messages } = TestValidation.validationTestBearerStreamable( { baseUrl, routePath, bearerToken } )
        if( !status ) {
            TestValidation.error( { messages } )
        }

        const testResult = await BearerTester.runTest( {
            baseUrl,
            routePath,
            bearerToken,
            timeout,
            testUnauthorized,
            expectedUnauthorizedStatus
        } )

        return testResult
    }


    static async testOAuthStreamable( { baseUrl, routePath, oauth21Config, browserTimeout = 90000, silent = false, testUnauthorized = true, expectedUnauthorizedStatus = 401, useDynamicRegistration = false } ) {
        // Skip validation of oauth21Config if using dynamic registration
        if( !useDynamicRegistration ) {
            const { status, messages } = TestValidation.validationTestOAuthStreamable( {
                baseUrl,
                routePath,
                oauth21Config,
                browserTimeout,
                silent
            } )
            if( !status ) {
                TestValidation.error( { messages } )
            }
        } else {
            // Only validate base parameters for dynamic registration
            const { status, messages } = TestValidation.validationTestStreamableRoute( { baseUrl, routePath } )
            if( !status ) {
                TestValidation.error( { messages } )
            }
        }

        const testResult = await OAuthTester.runTest( {
            baseUrl,
            routePath,
            oauth21Config,
            browserTimeout,
            silent,
            testUnauthorized,
            expectedUnauthorizedStatus,
            useDynamicRegistration
        } )

        return testResult
    }
}


// Process exit handlers for automatic cleanup
const cleanupScripts = () => {
    const runningScripts = OAuthMiddlewareTester.getRunningScripts()
    if( runningScripts ) {
        runningScripts.forEach( ( scriptProcess ) => {
            if( !scriptProcess.killed ) {
                scriptProcess.kill()
            }
        } )
    }
}

process.on( 'exit', cleanupScripts )

process.on( 'SIGINT', () => {
    cleanupScripts()
    process.exit( 0 )
} )

process.on( 'SIGTERM', () => {
    cleanupScripts()
    process.exit( 0 )
} )


export { OAuthMiddlewareTester }