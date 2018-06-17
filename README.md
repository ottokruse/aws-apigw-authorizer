# AWS Lambda Authorizer for API Gateway

This is an implementation in NodeJS of an authorizer function for AWS API Gateway. 

(i.e. an implementation of this: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

<!-- TOC -->

- [1. Supported Authentication Mechanisms](#1-supported-authentication-mechanisms)
- [2. How to use](#2-how-to-use)
    - [2.1. Basic usage](#21-basic-usage)
    - [2.2. Customize Policy Builder](#22-customize-policy-builder)
    - [2.3. Customize Context Builder](#23-customize-context-builder)
    - [2.4. Customize Auth Checks](#24-customize-auth-checks)
    - [2.5. Customize Determination of principalId](#25-customize-determination-of-principalid)
- [3. Supported Environment Variables:](#3-supported-environment-variables)
    - [3.1. ALLOWED_IP_ADDRESSES](#31-allowed_ip_addresses)
    - [3.2. BASIC_AUTH_USER_XXX](#32-basic_auth_user_xxx)
    - [3.3. AUDIENCE_URI, ISSUER_URI, JWKS_URI](#33-audience_uri-issuer_uri-jwks_uri)

<!-- /TOC -->

## 1. Supported Authentication Mechanisms

The authorizer supports these authentication mechanisms:

- JWT
- Basic Authentication

Also, the authorizer can be configured to only allow certain source IP's (see below).

## 2. How to use

### 2.1. Basic usage

Create a Lambda function in AWS using **Node 8.10** runtime and use the following code:

```js
const lambdaAuthorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer();

exports.handler = lambdaAuthorizer.handler.bind(lambdaAuthorizer);
```

Of course you will have to create a deployment package to include `aws-apigw-authorizer` and it's dependencies.

    npm install aws-apigw-authorizer

See instructions here: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-create-deployment-pkg.html

Make sure you give the lambda the right environment variables, see below.

Use the Lambda function you created for your API Gateway Authorizer. Make sure the "Lambda Event Payload" of that authorizer is set to "Request" (explained here: https://aws.amazon.com/blogs/compute/using-enhanced-request-authorizers-in-amazon-api-gateway/). This will (a.o.) give access to the source IP-address of calls to your API.

### 2.2. Customize Policy Builder

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

const lambdaAuthorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer(
    { policyBuilder: customPolicyBuilder }
);

exports.handler = lambdaAuthorizer.handler.bind(lambdaAuthorizer);
```

If a custom policy builder is not provided, the default policy builder will be used, which will grant the user access to invoke all resources of the API using any HTTP method.

### 2.3. Customize Context Builder

A custom function can be provided for setting the authorization context (https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html). The custom function will be called after succesfull authentication:

```js
// May return promise or synchronous result as below
function customContextBuilder(event, principal, decodedToken) {
    return {
        name: decodedToken['sub'],
        foo: 'bar'
    }
}

const authorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer(
    { contextBuilder: customContextBuilder }
);

exports.handler = authorizer.handler.bind(authorizer);
```

If you throw an error anywhere in the customContextBuilder the request will be denied (HTTP 401).

### 2.4. Customize Auth Checks

A custom function can be provided in which you can include your own checks. If you throw an error anywhere in that function the request will be denied (HTTP 401).

```js
// May return promise or synchronous result as below
function customAuthChecks(event, principal, decodedToken) {
    if (!event.headers['X-SHOULD-BE-PRESENT']) {
        throw new Error('HTTP header X-SHOULD-BE-PRESENT is required');
    }
}

const authorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer(
    { authChecks: customAuthChecks }
);

exports.handler = authorizer.handler.bind(authorizer);
```

### 2.5. Customize Determination of principalId

If you want to take control of the determination of the principalId that is used in the AWS policy and cloudwatch logging, specify a custom JwtPrincipalIdSelectorFunction.

This is only useful for JWT auth, because for Basic Authentication the username will be used as principalId.

```js
// May return promise or synchronous result as below
function customJwtPrincipalIdSelectorFunction(event, decodedToken) {
    return 'principalId of your liking';
}

const authorizer = new (require('aws-apigw-authorizer')).ApiGatewayAuthorizer(
    { jwtPrincipalIdSelectorFunction: customJwtPrincipalIdSelectorFunction }
);

exports.handler = authorizer.handler.bind(authorizer);
```

If a custom principalId selector for JWT is not provided, the default principalId selector for JWT will be used which will try the following JWT claims in order, the first one that has a value will be used:

1. `email`
1. `upn`
1. `sub`

## 3. Supported Environment Variables:

Your lambda function should be configured using the following environment variables:

- ALLOWED_IP_ADDRESSES (mandatory)
- BASIC_AUTH_USER_xxx (mandatory for Basic Authentication)
- AUDIENCE_URI (mandatory for use of JWT Authentication)
- ISSUER_URI (mandatory for use of JWT Authentication)
- JWKS_URI (mandatory for use of JWT Authentication)

### 3.1. ALLOWED_IP_ADDRESSES

It is mandatory to explicitly specify which remote IP adresses/address ranges are allowed to access the API.

ALLOWED_IP_ADDRESSES can be set to `0.0.0.0/0` for public access.

Individual IP-addresses can be specified, or ranges using CIDR-notation, multiple entries separated bij comma's.

Example:

    ALLOWED_IP_ADDRESSES=213.149.225.141/32,213.149.225.141


### 3.2. BASIC_AUTH_USER_XXX

Users allowed access through HTTP Basic Authentication can be configured as follows:

    BASIC_AUTH_USER_mike=mikespassword
    BASIC_AUTH_USER_lisa=lisaspassword

This is an optional environment key, without which Basic Authentication is not enabled.


### 3.3. AUDIENCE_URI, ISSUER_URI, JWKS_URI

For JWT authentication provide a value for `AUDIENCE_URI`, `ISSUER_URI` and `JWKS_URI`

Example:

    AUDIENCE_URI=123456cc-cd12-1234-ff66-7897fabcd12
    ISSUER_URI=https://sts.yourserver.com/876abc-ab12-8765-ff43-75232abc/
    JWKS_URI=https://login.yourserver.com/common/discovery/keys'

These are optional environment keys, without which JWT Authentication is not enabled.
