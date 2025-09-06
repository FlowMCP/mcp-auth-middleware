import crypto from 'crypto'


class PKCEGenerator {
    static generateCodeVerifier() {
        const verifier = crypto.randomBytes( 32 ).toString( 'base64url' )
        
        return { verifier }
    }


    static generateCodeChallenge( { verifier } ) {
        const challenge = crypto
            .createHash( 'sha256' )
            .update( verifier )
            .digest( 'base64url' )
        
        return { challenge }
    }


    static generatePKCEPair() {
        const { verifier } = this.generateCodeVerifier()
        const { challenge } = this.generateCodeChallenge( { verifier } )
        
        const pair = {
            codeVerifier: verifier,
            codeChallenge: challenge,
            codeChallengeMethod: 'S256'
        }

        return { pair }
    }


    static verifyChallenge( { verifier, challenge } ) {
        const { challenge: expectedChallenge } = this.generateCodeChallenge( { verifier } )
        const isValid = challenge === expectedChallenge
        
        return { isValid }
    }
}

export { PKCEGenerator }