import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';

export type Jwt = { [key: string]: any }

let _jwksClient: jwksClient.JwksClient;
let _jwksClientUri: string;

async function getSigningKey(jwksUri: string, kid: string) {
    if (!_jwksClient || jwksUri !== _jwksClientUri || process.env.JWKS_NO_CACHE) {
        _jwksClientUri = jwksUri;
        _jwksClient = jwksClient({ cache: true, rateLimit: true, jwksUri });
    }
    return new Promise<jwksClient.Jwk>((resolve, reject) => {
        _jwksClient.getSigningKey(kid, (err, jwk) => err ? reject(err) : resolve(jwk));
    });
}

export async function validate(jwtToken: string) {
    if (!process.env.AUDIENCE_URI || !process.env.ISSUER_URI || !process.env.JWKS_URI) {
        throw new Error('JWT validator configuration incomplete. Need AUDIENCE_URI, ISSUER_URI, JWKS_URI');
    }

    const expectedAudience = process.env.AUDIENCE_URI;
    const expectedIssuer = process.env.ISSUER_URI;
    const jwksUri = process.env.JWKS_URI;

    const decodedJwtToken = jwt.decode(jwtToken, { complete: true }) as Jwt;
    if (!decodedJwtToken) {
        throw new Error('Cannot parse JWT token');
    }
    const kid = decodedJwtToken['header']['kid'];
    const jwk = await getSigningKey(jwksUri, kid);
    const signingKey = jwk.publicKey || jwk.rsaPublicKey;
    if (!signingKey) {
        throw new Error('Cannot determine the key with which the token was signed');
    }
    const verificationOptions = {
        audience: expectedAudience,
        issuer: expectedIssuer,
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
