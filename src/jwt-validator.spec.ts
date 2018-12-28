import * as jwtValidator from './jwt-validator';
import { expect, use } from 'chai';
import * as nock from 'nock';
const chaiAsPromised = require('chai-as-promised');

use(chaiAsPromised);

describe('JWT validator', () => {

    const config = {
        idToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5VTXhOVVExUkRreFJrSkdORVJDUTBaQ1FrUkRSamN4UmpJd1JETkJORGMyUWpVNU1EZEVNUSJ9.eyJuaWNrbmFtZSI6ImFwaS1ndy1hdXRoLXRlc3RlciIsIm5hbWUiOiJhcGktZ3ctYXV0aC10ZXN0ZXJAc2hhcmtsYXNlcnMuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyL2IxNWJjNjExZjNkMTI1OGEyODBiMDYzNDI3MjY0YjU1P3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYXAucG5nIiwidXBkYXRlZF9hdCI6IjIwMTgtMDYtMTZUMTU6MDE6MzUuNTA1WiIsImVtYWlsIjoiYXBpLWd3LWF1dGgtdGVzdGVyQHNoYXJrbGFzZXJzLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL290dG9rcnVzZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWIyNTI1OTcwNGUwZTMwYmY3MmEwZDUxIiwiYXVkIjoieUVOd3VDMmJqUUd1M1FKNVp2eDhFNmJlbDJFdXZ2RkIiLCJpYXQiOjE1MjkxNjEyOTUsImV4cCI6MTUyOTE5NzI5NX0.Wx9mCII49WTMWoUu72qXFof8J4umyKzuc0h_iHWNTDgGhBt8Pxp2LQ7hjNEV4F6sOFBM11uTEiCvrExBiHlnHpgItuoLqRoPeOKdXHG63ztgg-SfzWyXvt3ywZtRXwivge5oUPIbSm2hNhoGgKRUwk-VlRnFjl7RGt3nOK7TOLeSjmr50z7p6ugIVk42gLffg3xKfZ-XT4Z1S_0pY6-ok29GrXHwdz3vb2QbtGkyfaYoK19TMN6itc-vZeEQzHjvQsMRiq2ZUOK1kmS7wQuxtx7_aqNibXwK2YVzTLnG5uwnk8orhepH2SAF96UbXTa0YbT9zepgErhSuVt6XyFaLQ',
        accessToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5VTXhOVVExUkRreFJrSkdORVJDUTBaQ1FrUkRSamN4UmpJd1JETkJORGMyUWpVNU1EZEVNUSJ9.eyJpc3MiOiJodHRwczovL290dG9rcnVzZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiVlY2a0VBWVQ0UmRoaHo0bWRGellJbUEyNFA4dkp0TjFAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vYXBpLm90dG9yb2NrZXQuY29tIiwiaWF0IjoxNTI4OTY3ODMyLCJleHAiOjE1MjkwNTQyMzIsImF6cCI6IlZWNmtFQVlUNFJkaGh6NG1kRnpZSW1BMjRQOHZKdE4xIiwic2NvcGUiOiJwcm9maWxlIG9wZW5pZCIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.TsczOoJxRrfdkUNq8czVtFr7SMoc6WHZWYkuiFLluBUHVUDP1WY7c1e5r3DHOQMxxRxTuoV2DNSEipBWnsNT7d9JCHQFIl5KZTI4kv4u9Q3YV44gIB00gzxYwrbEsw3SIkvLjkPfJFhWs0vssZse-kVCnjODiVTXARXsf5Mumny0gdrykU1onoYSW-bmnm1mrTk1gmH2nM1vmqbd4csWaX4-b2zo07ZTLJlFON8_8lajwCLAWgYuYHLYAN0vpwQyi8tczcWdjnlibYXamjLrg2z9ooYoHD0R99GgU4Xu3TOyb3VZ3rfS31Cpd5gsm5FW-CupgPwyi5Wn2NuCjgJcog',
        userInfoAudience: 'yENwuC2bjQGu3QJ5Zvx8E6bel2EuvvFB',
        apiAudience: 'https://api.ottorocket.com',
        issuer: 'https://ottokruse.eu.auth0.com/',
        jwksUri: 'https://ottokruse.eu.auth0.com/.well-known/jwks.json'
    };

    beforeEach(() => {
        process.env.JWT_NO_EXPIRATION = '1';
        process.env.JWKS_NO_CACHE = '1';
        setupNockMocks();
    });

    afterEach(() => {
        delete process.env.JWT_NO_EXPIRATION;
        delete process.env.JWKS_NO_CACHE;
        delete process.env.AUDIENCE_URI;
        delete process.env.ISSUER_URI;
        delete process.env.JWKS_URI;
    });

    it('JWT validation id token Auth0 succeeds', async () => {
        process.env.AUDIENCE_URI = config.userInfoAudience;
        process.env.ISSUER_URI = config.issuer;
        process.env.JWKS_URI = config.jwksUri;

        const expectation = {
            "nickname": "api-gw-auth-tester",
            "name": "api-gw-auth-tester@sharklasers.com",
            "picture": "https://s.gravatar.com/avatar/b15bc611f3d1258a280b063427264b55?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fap.png",
            "updated_at": "2018-06-16T15:01:35.505Z",
            "email": "api-gw-auth-tester@sharklasers.com",
            "email_verified": true,
            "iss": "https://ottokruse.eu.auth0.com/",
            "sub": "auth0|5b25259704e0e30bf72a0d51",
            "aud": "yENwuC2bjQGu3QJ5Zvx8E6bel2EuvvFB",
            "iat": 1529161295,
            "exp": 1529197295
        };
        expect(await jwtValidator.validate(config.idToken)).to.deep.equal(expectation);
    });

    it('JWT validation access token Auth0 succeeds', async () => {
        process.env.AUDIENCE_URI = config.apiAudience;
        process.env.ISSUER_URI = config.issuer;
        process.env.JWKS_URI = config.jwksUri;

        const expectation = {
            iss: 'https://ottokruse.eu.auth0.com/',
            sub: 'VV6kEAYT4Rdhhz4mdFzYImA24P8vJtN1@clients',
            aud: 'https://api.ottorocket.com',
            iat: 1528967832,
            exp: 1529054232,
            azp: 'VV6kEAYT4Rdhhz4mdFzYImA24P8vJtN1',
            scope: 'profile openid',
            gty: 'client-credentials'
        };
        expect(await jwtValidator.validate(config.accessToken)).to.deep.equal(expectation);
    });

    it('JWT validation fails - token expired', async () => {
        process.env.AUDIENCE_URI = config.apiAudience;
        process.env.ISSUER_URI = config.issuer;
        process.env.JWKS_URI = config.jwksUri;

        delete process.env.JWT_NO_EXPIRATION;
        await expect(jwtValidator.validate(config.accessToken)).to.be.rejectedWith('jwt expired');
    });

    it('JWT validation fails - certs of JWKS invalid - kid not found', async () => {
        process.env.AUDIENCE_URI = config.apiAudience;
        process.env.ISSUER_URI = config.issuer;
        process.env.JWKS_URI = config.jwksUri;

        nock.cleanAll();
        nock('https://ottokruse.eu.auth0.com')
            .get('/.well-known/jwks.json')
            .replyWithFile(200, `${__dirname}/../test/jwks-Auth0-corrupt-kid.mock.json`);

        await expect(jwtValidator.validate(config.accessToken)).to.be.rejectedWith('Unable to find a signing key that matches');
    });

    it('JWT validation fails - certs of JWKS invalid - key is corrupt', async () => {
        process.env.AUDIENCE_URI = config.apiAudience;
        process.env.ISSUER_URI = config.issuer;
        process.env.JWKS_URI = config.jwksUri;

        nock.cleanAll();
        nock('https://ottokruse.eu.auth0.com')
            .get('/.well-known/jwks.json')
            .replyWithFile(200, `${__dirname}/../test/jwks-Auth0-corrupt-key.mock.json`);

        await expect(jwtValidator.validate(config.accessToken)).to.be.rejected;
    });

});

function setupNockMocks() {
    nock('https://ottokruse.eu.auth0.com')
        .get('/.well-known/jwks.json')
        .replyWithFile(200, `${__dirname}/../test/jwks-Auth0.mock.json`);
}
