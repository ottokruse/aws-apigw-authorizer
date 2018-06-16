# AWS Lambda Authorizer for API Gateway

## This is an AWS Lambda Authorizer for API Gateway

This is an implementation in NodeJS of a custom authorizer function for AWS API Gateway. (https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

This custom authorizer supports these authentication mechanisms:

- JWT
- Basic Authentication

In the default configuration this authorizer will grant the user access to invoke all resources of the API using any HTTP method.

Configuration can be provided through Lambda environment variables (see below).

## Implement an API Gateway Authorizer Lambda functions as follows:

```js
const lambdaAuthorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer();

exports.handler = lambdaAuthorizer.handler.bind(lambdaAuthorizer);
```

### Custom Policy Builder

A custom function can be provided for building custom AWS IAM policies. The custom function will be called after succesfull authentication:

```js
// May return promise or synchronous result as below
function customPolicyBuilder(event, principal, decodedJwt) {
    // event: the raw event that the authorizer lambda function receives from API Gateway 
    // principal: the username of the authenticated user
    // decodedJwt: the decoded JWT. Only present if authentication was based on JWT
    return {  
        "principalId": "your principal - just a name",  
        "policyDocument": {  
            "Version": "2012-10-17",  
            "Statement": [  
                {  
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:execute-api:eu-west-1:region:api-id/stage/*/*"
                    ],
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": [
                                "123.456.789.123/32"
                            ]
                        }
                    }
                }
            ]
        }
    }
}

const lambdaAuthorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer({ policyBuilder: customPolicyBuilder });

exports.handler = lambdaAuthorizer.handler.bind(lambdaAuthorizer);
```

### Custom Context Builder

A custom function can be provided for setting the authorization context (https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html). The custom function will be called after succesfull authentication:

```js
// May return promise or synchronous result as below
function customContextBuilder(event, principal, decodedToken) {
    return {
        name: decodedToken['sub'],
        foo: 'bar'
    }
}

const authorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer({ contextBuilder: customContextBuilder});

exports.handler = authorizer.handler.bind(authorizer);
```

If you throw an error anywhere in the customContextBuilder the request will be denied (HTTP 401).

### Custom Auth Checks

A custom function can be provided in which you can include your own checks. If you throw an error anywhere in that function the request will be denied (HTTP 401).

```js
// May return promise or synchronous result as below
function customAuthChecks(event, principal, decodedToken) {
    if (!event.headers['X-SHOULD-BE-PRESENT']) {
        throw new Error('HTTP header X-SHOULD-BE-PRESENT is required');
    }
}

const authorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer({ authChecks: customAuthChecks});

exports.handler = authorizer.handler.bind(authorizer);
```

## Configuration through environment variables:

Your lambda function should be configured using the following environment variables.


### ALLOWED_IP_ADDRESSES

It is mandatory to explicitly specify which remote IP adresses/address rangers are allowed to access the API.

ALLOWED_IP_ADDRESSES can be set to `0.0.0.0/0` for public access.

Individual IP-addresses can be specified, or ranges using CIDR-notation, multiple entries separated bij comma's.

Example:

    ALLOWED_IP_ADDRESSES=213.149.225.141/32,213.149.225.141


### BASIC_AUTH_USER_XXX

Users allowed access through HTTP Basic Authentication can be configured as follows:

    BASIC_AUTH_USER_mike=mikespassword
    BASIC_AUTH_USER_lisa=lisaspassword

This is an optional environment key, without which Basic Authentication is not enabled.


### AUDIENCE_URI, ISSUER_URI, JWKS_URI

For JWT authentication provide a value for `AUDIENCE_URI`, `ISSUER_URI` and `JWKS_URI`

Example:

    AUDIENCE_URI=123456cc-cd12-1234-ff66-7897fabcd12
    ISSUER_URI=https://sts.yourserver.com/876abc-ab12-8765-ff43-75232abc/
    JWKS_URI=https://login.yourserver.com/common/discovery/keys'

These are optional environment keys, without which JWT Authentication is not enabled.
