import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';

export type Jwt = { [key: string]: any }

let _jwksClientMap: Map<string,jwksClient.JwksClient> = new Map;

async function getSigningKey(jwksUriList: string[], kid: string) {
    let error: Error;
    return new Promise<jwksClient.Jwk>(async(resolve, reject) => {
        for (const jwksUri of jwksUriList) {
            if (!_jwksClientMap.size || !_jwksClientMap.has(jwksUri) || process.env.JWKS_NO_CACHE) {
                _jwksClientMap.set(jwksUri, jwksClient({ cache: true, rateLimit: true, jwksUri }));
            }
            error = await new Promise<Error>((resolveError, rejectError) => {
                const jwksClient = _jwksClientMap.get(jwksUri);
                jwksClient ? jwksClient.getSigningKey(kid, (err, key) => key ? resolve(key) : resolveError(err)) : rejectError();
            });
        }
        reject(error);
    });
}

export async function validate(jwtToken: string) {
    if (!process.env.AUDIENCE_URI || !process.env.ISSUER_URI || !process.env.JWKS_URI) {
        throw new Error('JWT validator configuration incomplete. Need AUDIENCE_URI, ISSUER_URI, JWKS_URI');
    }

    const expectedAudienceList = process.env.AUDIENCE_URI.split(',');
    const expectedIssuerList = process.env.ISSUER_URI.split(',');
    const jwksUriList = process.env.JWKS_URI.split(',');

    const decodedJwtToken = jwt.decode(jwtToken, { complete: true }) as Jwt;
    if (!decodedJwtToken) {
        throw new Error('Cannot parse JWT token');
    }
    const kid = decodedJwtToken['header']['kid'];
    const jwk = await getSigningKey(jwksUriList, kid);
    const signingKey = jwk.publicKey || jwk.rsaPublicKey;
    if (!signingKey) {
        throw new Error('Cannot determine the key with which the token was signed');
    }
    const verificationOptions = {
        audience: expectedAudienceList,
        issuer: expectedIssuerList,
        ignoreExpiration: false
    };
    // For testing purposes JWT expiration can be disregarded using an environment variable
    if (['1', 'true', 'TRUE', 'True'].indexOf(process.env.JWT_NO_EXPIRATION || '') > -1) {
        verificationOptions.ignoreExpiration = true;
    }
    // Verify the JWT
    // This either rejects (JWT not valid), or resolves withe the decoded token (object or string)
    return new Promise<Jwt>((resolve, reject) => {
        jwt.verify(jwtToken, signingKey, verificationOptions, (err, decodedJwtToken) => err ? reject(err) : resolve(decodedJwtToken as Jwt));
    });
}
