import * as authorizer from './authorizer';
import { expect, use } from 'chai';
import * as nock from 'nock';
const chaiAsPromised = require('chai-as-promised');

use(chaiAsPromised);

describe('authorizer', () => {

  let event: any;
  let lambdaAuthorizer: authorizer.ApiGatewayAuthorizer;
  async function callHandler(event: any) {
    return new Promise((resolve, reject) => {
      function cb(err: any, res: any) {
        err ? reject(new Error(err)) : resolve(res)
      };
      lambdaAuthorizer.handler(event, <AWSLambda.Context>{}, cb);
    });
  }

  const config = {
    idToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5VTXhOVVExUkRreFJrSkdORVJDUTBaQ1FrUkRSamN4UmpJd1JETkJORGMyUWpVNU1EZEVNUSJ9.eyJuaWNrbmFtZSI6ImFwaS1ndy1hdXRoLXRlc3RlciIsIm5hbWUiOiJhcGktZ3ctYXV0aC10ZXN0ZXJAc2hhcmtsYXNlcnMuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyL2IxNWJjNjExZjNkMTI1OGEyODBiMDYzNDI3MjY0YjU1P3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYXAucG5nIiwidXBkYXRlZF9hdCI6IjIwMTgtMDYtMTZUMTU6MDE6MzUuNTA1WiIsImVtYWlsIjoiYXBpLWd3LWF1dGgtdGVzdGVyQHNoYXJrbGFzZXJzLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL290dG9rcnVzZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWIyNTI1OTcwNGUwZTMwYmY3MmEwZDUxIiwiYXVkIjoieUVOd3VDMmJqUUd1M1FKNVp2eDhFNmJlbDJFdXZ2RkIiLCJpYXQiOjE1MjkxNjEyOTUsImV4cCI6MTUyOTE5NzI5NX0.Wx9mCII49WTMWoUu72qXFof8J4umyKzuc0h_iHWNTDgGhBt8Pxp2LQ7hjNEV4F6sOFBM11uTEiCvrExBiHlnHpgItuoLqRoPeOKdXHG63ztgg-SfzWyXvt3ywZtRXwivge5oUPIbSm2hNhoGgKRUwk-VlRnFjl7RGt3nOK7TOLeSjmr50z7p6ugIVk42gLffg3xKfZ-XT4Z1S_0pY6-ok29GrXHwdz3vb2QbtGkyfaYoK19TMN6itc-vZeEQzHjvQsMRiq2ZUOK1kmS7wQuxtx7_aqNibXwK2YVzTLnG5uwnk8orhepH2SAF96UbXTa0YbT9zepgErhSuVt6XyFaLQ',
    accessToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5VTXhOVVExUkRreFJrSkdORVJDUTBaQ1FrUkRSamN4UmpJd1JETkJORGMyUWpVNU1EZEVNUSJ9.eyJpc3MiOiJodHRwczovL290dG9rcnVzZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiVlY2a0VBWVQ0UmRoaHo0bWRGellJbUEyNFA4dkp0TjFAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vYXBpLm90dG9yb2NrZXQuY29tIiwiaWF0IjoxNTI4OTY3ODMyLCJleHAiOjE1MjkwNTQyMzIsImF6cCI6IlZWNmtFQVlUNFJkaGh6NG1kRnpZSW1BMjRQOHZKdE4xIiwic2NvcGUiOiJwcm9maWxlIG9wZW5pZCIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.TsczOoJxRrfdkUNq8czVtFr7SMoc6WHZWYkuiFLluBUHVUDP1WY7c1e5r3DHOQMxxRxTuoV2DNSEipBWnsNT7d9JCHQFIl5KZTI4kv4u9Q3YV44gIB00gzxYwrbEsw3SIkvLjkPfJFhWs0vssZse-kVCnjODiVTXARXsf5Mumny0gdrykU1onoYSW-bmnm1mrTk1gmH2nM1vmqbd4csWaX4-b2zo07ZTLJlFON8_8lajwCLAWgYuYHLYAN0vpwQyi8tczcWdjnlibYXamjLrg2z9ooYoHD0R99GgU4Xu3TOyb3VZ3rfS31Cpd5gsm5FW-CupgPwyi5Wn2NuCjgJcog',
    userInfoAudience: 'yENwuC2bjQGu3QJ5Zvx8E6bel2EuvvFB',
    apiAudience: 'https://api.ottorocket.com',
    issuer: 'https://ottokruse.eu.auth0.com/',
    jwksUri: 'https://ottokruse.eu.auth0.com/.well-known/jwks.json'
  };

  beforeEach(() => {
    event = {
      methodArn: 'arn:aws:lambda:eu-west-1:123456789000:function:function-name',
      headers: {},
      requestContext: {
        identity: {
          sourceIp: '192.168.0.1',
        }
      }
    };

    process.env.ALLOWED_IP_ADDRESSES = '192.168.0.1/32,123.456.789.012/0';
    process.env.BASIC_AUTH_USER_MDTPI = 'ourpassword';
    process.env.AUDIENCE_URI = config.apiAudience;
    process.env.ISSUER_URI = config.issuer;
    process.env.JWKS_URI = config.jwksUri;
    process.env.JWT_NO_EXPIRATION = '1';
    process.env.JWKS_NO_CACHE = '1';
    lambdaAuthorizer = new authorizer.ApiGatewayAuthorizer({
      contextBuilder: (_event, principalId, _token) => ({ name: principalId })
    });
    setupNockMocks();
  });

  it('JWT validation Auth0 succeeds', async () => {
    event.headers.Authorization = `Bearer ${config.accessToken}`;

    const expectation = {
      "principalId": "VV6kEAYT4Rdhhz4mdFzYImA24P8vJtN1@clients",
      "context": {
        "name": "VV6kEAYT4Rdhhz4mdFzYImA24P8vJtN1@clients"
      },
      "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "execute-api:Invoke",
            "Effect": "Allow",
            "Resource": [
              "arn:aws:execute-api:eu-west-1:123456789000:function/*/*/*"
            ]
          }
        ]
      }
    };

    return expect(callHandler(event)).to.eventually.deep.equal(expectation);

  });

  it('JWT validation can succeed on any IP if configured', async () => {
    event.headers.Authorization = `Bearer ${config.accessToken}`;
    process.env.ALLOWED_IP_ADDRESSES = '192.168.0.1/32,0.0.0.0/0';
    event.requestContext.identity.sourceIp = "127.0.0.1";
    await expect(callHandler(event)).to.not.be.rejected;
  });

  it('JWT validation fails because JWT expired', async () => {
    event.headers.Authorization = `Bearer ${config.accessToken}`;
    delete process.env.JWT_NO_EXPIRATION;
    return expect(callHandler(event)).to.be.rejected;
  });

  it('JWT validation fails because env var has not been set: ALLOWED_IP_ADDRESSES', async () => {
    event.headers.Authorization = `Bearer ${config.accessToken}`;
    delete process.env.ALLOWED_IP_ADDRESSES;
    await expect(callHandler(event)).to.be.rejected;
  });

  it('JWT validation fails because source IP not within ALLOWED_IP_ADDRESSES', async () => {
    event.headers.Authorization = `Bearer ${config.accessToken}`;
    event.requestContext.identity.sourceIp = "127.0.0.1";
    await expect(callHandler(event)).to.be.rejected;
  });

  it('JWT validation fails because token is corrupt', async () => {
    event.headers.Authorization = `Bearer CorrupteBoel`;
    await expect(callHandler(event)).to.be.rejected;
  });

  it('JWT validation ID token succeeds', async () => {
    event.headers.Authorization = `Bearer ${config.idToken}`;
    process.env.AUDIENCE_URI = config.userInfoAudience;

    const expectation = {
      "principalId": "api-gw-auth-tester@sharklasers.com",
      "context": {
        "name": "api-gw-auth-tester@sharklasers.com"
      },
      "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "execute-api:Invoke",
            "Effect": "Allow",
            "Resource": [
              "arn:aws:execute-api:eu-west-1:123456789000:function/*/*/*"
            ]
          }
        ]
      }
    };

    await expect(callHandler(event)).to.eventually.deep.equal(expectation);
  });

  it('Basic auth validatie slaagt', async () => {
    event.headers.Authorization = 'Basic ' + new Buffer(`MDTPI:${process.env.BASIC_AUTH_USER_MDTPI}`).toString('base64');

    const expectation = {
      "principalId": "MDTPI",
      "context": {
        "name": "MDTPI"
      },
      "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "execute-api:Invoke",
            "Effect": "Allow",
            "Resource": [
              "arn:aws:execute-api:eu-west-1:123456789000:function/*/*/*"
            ]
          }
        ]
      }
    };

    await expect(callHandler(event)).to.eventually.deep.equal(expectation);
  });

  it('Basic auth validatie faalt want verkeerd password', async () => {
    event.headers.Authorization = 'Basic ' + new Buffer('MDTPI:WrongPassword').toString('base64');

    await expect(callHandler(event)).to.be.rejected;
  });

  it('Basic auth validatie faalt want onbekende user', async () => {
    event.headers.Authorization = 'Basic ' + new Buffer(`WrongUser:${process.env.BASIC_AUTH_USER_MDTPI}`).toString('base64');

    await expect(callHandler(event)).to.be.rejected;
  });

  it('Basic auth validatie faalt want corrupt token', async () => {
    event.headers.Authorization = `Basic THISISAWRONGTOKEN`;

    await expect(callHandler(event)).to.be.rejected;
  });

  it('Auth faalt want Authorization header is gevuld met onzin', async () => {
    event.headers.Authorization = `Onzin THISISAWRONGTOKEN`;

    await expect(callHandler(event)).to.be.rejected;
  });

  it('Auth faalt want Authorization header is er niet', async () => {
    delete event.headers.Authorization;

    await expect(callHandler(event)).to.be.rejected;
  });

});

function setupNockMocks() {
  nock('https://mijnnvs.eu.auth0.com')
    .get('/.well-known/jwks.json')
    .replyWithFile(200, `${__dirname}/../test/jwks-Auth0.mock.json`);
}
