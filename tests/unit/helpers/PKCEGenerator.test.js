import { jest } from '@jest/globals'
import { PKCEGenerator } from '../../../src/task/helpers/PKCEGenerator.mjs'


describe( 'PKCEGenerator', () => {
    describe( 'generateCodeVerifier', () => {
        test( 'generates a valid code verifier', () => {
            const { verifier } = PKCEGenerator.generateCodeVerifier()
            
            expect( verifier ).toBeDefined()
            expect( typeof verifier ).toBe( 'string' )
            expect( verifier.length ).toBeGreaterThanOrEqual( 43 )
            expect( verifier.length ).toBeLessThanOrEqual( 128 )
        } )

        test( 'generates unique verifiers', () => {
            const { verifier: v1 } = PKCEGenerator.generateCodeVerifier()
            const { verifier: v2 } = PKCEGenerator.generateCodeVerifier()
            
            expect( v1 ).not.toBe( v2 )
        } )
    } )

    describe( 'generateCodeChallenge', () => {
        test( 'generates valid S256 challenge from verifier', () => {
            const { verifier } = PKCEGenerator.generateCodeVerifier()
            const { challenge } = PKCEGenerator.generateCodeChallenge( { verifier } )
            
            expect( challenge ).toBeDefined()
            expect( typeof challenge ).toBe( 'string' )
            expect( challenge.length ).toBeGreaterThan( 0 )
        } )

        test( 'generates consistent challenge for same verifier', () => {
            const { verifier } = PKCEGenerator.generateCodeVerifier()
            const { challenge: c1 } = PKCEGenerator.generateCodeChallenge( { verifier } )
            const { challenge: c2 } = PKCEGenerator.generateCodeChallenge( { verifier } )
            
            expect( c1 ).toBe( c2 )
        } )
    } )

    describe( 'generatePKCEPair', () => {
        test( 'generates complete PKCE pair', () => {
            const { pair } = PKCEGenerator.generatePKCEPair()
            
            expect( pair ).toBeDefined()
            expect( pair.codeVerifier ).toBeDefined()
            expect( pair.codeChallenge ).toBeDefined()
            expect( pair.codeChallengeMethod ).toBe( 'S256' )
        } )
    } )

    describe( 'verifyChallenge', () => {
        test( 'verifies valid challenge-verifier pair', () => {
            const { pair } = PKCEGenerator.generatePKCEPair()
            const { isValid } = PKCEGenerator.verifyChallenge( {
                verifier: pair.codeVerifier,
                challenge: pair.codeChallenge
            } )
            
            expect( isValid ).toBe( true )
        } )

        test( 'rejects invalid challenge-verifier pair', () => {
            const { pair } = PKCEGenerator.generatePKCEPair()
            const { verifier: wrongVerifier } = PKCEGenerator.generateCodeVerifier()
            
            const { isValid } = PKCEGenerator.verifyChallenge( {
                verifier: wrongVerifier,
                challenge: pair.codeChallenge
            } )
            
            expect( isValid ).toBe( false )
        } )
    } )
} )