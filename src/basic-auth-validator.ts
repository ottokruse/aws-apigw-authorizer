const auth = require('basic-auth');

export function validate(token: string) {
    const userObj = auth.parse(`Basic ${token}`);
    if (!userObj) {
        throw new Error(`Cannot parse Basic Auth token ${token}`);
    }

    const expectedPassword = process.env[`BASIC_AUTH_USER_${userObj.name}`];

    if (!expectedPassword) {
        throw new Error(`Unknown user ${userObj.name} trying to authenticate with Basic Auth`);
    }

    if (expectedPassword !== userObj.pass) {
        throw new Error(`User ${userObj.name} password mismatch while trying to authenticatie with Basic Auth`);
    }

    return userObj;
}
