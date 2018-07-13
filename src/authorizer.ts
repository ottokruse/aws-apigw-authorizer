import * as basicAuthValidator from './basic-auth-validator';
import * as ipRangeCheck from 'ip-range-check';
import * as jwtValidator from './jwt-validator';
import * as AWSLambda from 'aws-lambda';
const awsPolicyLib = require('./aws-policy-lib');

export type PolicyBuilderFunction = (event: AWSLambda.CustomAuthorizerEvent, principalId: string, decodedToken?: Jwt) => AWSLambda.PolicyDocument | Promise<AWSLambda.PolicyDocument>;

export type ContextBuilderFunction = (event: AWSLambda.CustomAuthorizerEvent, principalId: string, decodedToken?: Jwt) => AWSLambda.AuthResponseContext | Promise<AWSLambda.AuthResponseContext> | void;

export type AuthChecksFunction = (event: AWSLambda.CustomAuthorizerEvent, principalId: string, decodedToken?: Jwt) => void | Promise<void>;

export type PrincipalId = string;

export type JwtPrincipalIdSelectorFunction = (event: AWSLambda.CustomAuthorizerEvent, decodedToken?: Jwt) => PrincipalId | Promise<PrincipalId>;

export interface AuthorizerConfig {
    policyBuilder?: PolicyBuilderFunction;
    contextBuilder?: ContextBuilderFunction;
    AuthChecks?: AuthChecksFunction;
    jwtPrincipalIdSelectorFunction?: JwtPrincipalIdSelectorFunction;
}

export type Jwt = string | object;

export class ApiGatewayAuthorizer {

    private policyBuilder: PolicyBuilderFunction;
    private contextBuilder: ContextBuilderFunction;
    private authChecks: AuthChecksFunction;
    private basicAuthenticationEnabled: boolean = false;
    private jwtAuthenticationEnabled: boolean = false;
    private principalIdSelectorFunction: JwtPrincipalIdSelectorFunction;

    constructor(authorizerConfig?: AuthorizerConfig) {

        // parse config
        this.policyBuilder = authorizerConfig && authorizerConfig.policyBuilder || defaultBuildPolicy;
        this.contextBuilder = authorizerConfig && authorizerConfig.contextBuilder || (() => undefined);
        this.authChecks = authorizerConfig && authorizerConfig.AuthChecks || (() => undefined);
        this.principalIdSelectorFunction = authorizerConfig && authorizerConfig.jwtPrincipalIdSelectorFunction || defaultJwtPrincipalIdSelector;

        // check environment for configured auth flavors
        if (Object.keys(process.env).filter(key => key.startsWith('BASIC_AUTH_USER_')).length) {
            this.basicAuthenticationEnabled = true;
        }
        if (process.env.AUDIENCE_URI && process.env.ISSUER_URI && process.env.JWKS_URI) {
            this.jwtAuthenticationEnabled = true;
        }
    }

    private assertSourceIp(event: AWSLambda.CustomAuthorizerEvent) {
        const sourceIp = event.requestContext && event.requestContext.identity.sourceIp;
        if (!sourceIp) {
            throw new Error('Source IP Cannot be determined');
        }
        return sourceIp;
    }

    private async authorize(event: AWSLambda.CustomAuthorizerEvent, principalId: string, decodedToken?: Jwt, ...logMessages: string[]) {
        await this.authChecks(event, principalId, decodedToken);
        const context = await this.contextBuilder(event, principalId, decodedToken);
        const policy = await this.policyBuilder(event, principalId, decodedToken);
        if (context) { Object.assign(policy, { context }) }
        this.log(event, 'Authorized:', ...logMessages);
        this.log(event, 'Built policy:', JSON.stringify(policy));
        return policy;
    }

    private deny(event: AWSLambda.CustomAuthorizerEvent, ...logMessages: string[]) {
        this.log(event, 'Denied:', ...logMessages);
        return 'Unauthorized';
    }

    private log(event: AWSLambda.CustomAuthorizerEvent, ...logMessages: string[]) {
        const sourceIp = this.assertSourceIp(event);
        console.log(`${[sourceIp, ...logMessages].join(' ')}`);
    }

    private async determineAuthorization(event: AWSLambda.CustomAuthorizerEvent) {

        // Sanity check: the Authorization header must be present
        if (!event.headers || !event.headers.Authorization) {
            throw new Error('Authorization HTTP header not present');
        }

        // Sanity check: the callers sourceIp should be present
        const sourceIp = this.assertSourceIp(event);

        // It is mandatory to set up ALLOWED_IP_ADDRESSES (0.0.0.0/0 is allowed)
        if (!process.env.ALLOWED_IP_ADDRESSES) {
            throw new Error('Cannot accept any source IP as ALLOWED_IP_ADDRESSES has not been set');
        }

        // Sanity check: the callers sourceIp should be an allowed ip
        if (process.env.ALLOWED_IP_ADDRESSES
            .split(',')
            .filter((ipRange) => ipRangeCheck(sourceIp, ipRange))
            .length === 0) {
            throw new Error('Source IP does not match with configured ALLOWED_IP_ADDRESSES');
        }

        // Validate credentials
        const [tokenType, token] = event.headers.Authorization.split(' ');
        if (tokenType === 'Bearer' && this.jwtAuthenticationEnabled) {
            const decodedToken = await jwtValidator.validate(token);
            const principalId = await this.principalIdSelectorFunction(event, decodedToken);
            return await this.authorize(event, principalId, decodedToken, `user ${principalId} using JWT`);
        } else if (tokenType === 'Basic' && this.basicAuthenticationEnabled) {
            const principalId = basicAuthValidator.validate(token).name;
            return await this.authorize(event, principalId, undefined, `user ${principalId} using Basic Auth`)
        } else {
            throw new Error(`Unauthorized: unsupported token type ${tokenType}`);
        }
    }

    public async handler(event: AWSLambda.CustomAuthorizerEvent, _context: AWSLambda.Context, callback: AWSLambda.Callback) {
        try {
            const policy = await this.determineAuthorization(event);
            callback(undefined, policy);
        } catch (err) {
            callback(this.deny(event, err));
        }
    }
}

function defaultBuildPolicy(event: AWSLambda.CustomAuthorizerEvent, principalId: string, _decodedToken?: Jwt): AWSLambda.PolicyDocument {
    // this function must generate a policy that is associated with the recognized principalId user identifier.
    // depending on your use case, you might store policies in a DB, or generate them on the fly

    // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
    // and will apply to subsequent calls to any method/resource in the RestApi
    // made with the same token

    // you can send a 401 Unauthorized response to the client by failing like so:
    // callback('Unauthorized');

    // if access is denied, the client will recieve a 403 Access Denied response
    // if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called

    // build apiOptions for the AuthPolicy
    const tmp = event.methodArn.split(':');
    const apiGatewayArnTmp = tmp[5].split('/');
    const awsAccountId = tmp[4];
    const apiOptions = {
        region: tmp[3],
        restApiId: apiGatewayArnTmp[0],
        stage: apiGatewayArnTmp[1],
    }

    // Allow access to all methods on the entire API
    // Such a wildcard is necessary in case of authorization caching because on the second call
    // a different resource or method may be used, which needs to be covered by the cached policy
    // otherwise it would be denied
    const policy = new awsPolicyLib.AuthPolicy(principalId, awsAccountId, apiOptions) as any;
    policy.allowMethod(awsPolicyLib.AuthPolicy.HttpVerb.ALL, '/*');

    return policy.build();

}

function defaultJwtPrincipalIdSelector(_event: AWSLambda.CustomAuthorizerEvent, decodedToken: Jwt): PrincipalId {
    let principalId: PrincipalId | undefined;
    if (decodedToken) {

        // Different identity providers put different claims on tokens
        // Auth0 seems to always include the 'email' claim
        // Microsoft seems to always put the e-mail address in 'upn' claim
        // Last resort  is the 'sub' claim which should mostly be present but contains an ID specific to the identity provider
        principalId = decodedToken['email'] || decodedToken['upn'] || decodedToken['sub'];
    }
    return principalId || 'Undeterminable Principal';
}
