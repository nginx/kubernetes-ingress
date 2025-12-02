/*
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 *
 * Copyright (C) 2025 Nginx, Inc.
 */

export default {
    auth,
    codeExchange,
    extractTokenClaims,
    logout,
    handleFrontChannelLogout
};

// The main authentication flow, called before serving a protected resource.
async function auth(r, afterSyncCheck) {
    // If there's a session cookie but session not synced, wait for sync
    if (r.variables.cookie_auth_token && !r.variables.session_jwt &&
        !afterSyncCheck && r.variables.zone_sync_leeway > 0) {
        waitForSessionSync(r, r.variables.zone_sync_leeway);
        return;
    }

    if (isNewSession(r)) {
        initiateNewAuth(r);
        return;
    }

    // No or expired ID token, but refresh token present, attempt to refresh
    const tokenset = await refreshTokens(r);
    if (!tokenset) {
        return;
    }

    // Validate refreshed ID token
    let claims;
    try {
        claims = await validateIdToken(r, tokenset.id_token);
    } catch (e) {
        // If validation failed, reset and reinitiate auth
        r.variables.refresh_token = "-";
        r.headersOut["Location"] = r.variables.request_uri;
        oidcError(r, 302, getRefId(r, "auth.validate"), e);
        return;
    }

    // Determine session ID and store session data
    const sessionId = getSessionId(r, false);
    storeSessionData(r, sessionId, claims, tokenset, true);

    r.log("OIDC success, refreshing session " + sessionId);

    // Continue processing original request
    retryOriginalRequest(r);
}

// The code exchange handler, called after IdP redirects back with an authorization code.
async function codeExchange(r) {
    // Check authorization code presence
    if (!r.variables.arg_code || r.variables.arg_code.length === 0) {
        const ref = getRefId(r, "codeExchange.code");
        if (r.variables.arg_error) {
            oidcError(r, 502, ref,
                new Error(`OIDC error receiving authorization code: ` +
                    `${r.variables.arg_error_description || r.variables.arg_error}`));
        } else {
            oidcError(r, 502, ref,
                new Error(`OIDC expected authorization code but received: ` +
                    `${r.variables.request_uri}`));
        }
        return;
    }

    // Exchange authorization code for tokens
    const tokenset = await exchangeCodeForTokens(r);
    if (!tokenset) {
        return;
    }

    // Validate ID token
    let claims;
    try {
        claims = await validateIdToken(r, tokenset.id_token);
    } catch (e) {
        oidcError(r, 500, getRefId(r, "codeExchange.validate"), e);
        return;
    }

    // Determine session ID and store session data for a new session
    const sessionId = getSessionId(r, true);
    storeSessionData(r, sessionId, claims, tokenset, true);

    r.log("OIDC success, creating session " + sessionId);

    // Set cookie and redirect to the originally requested URI
    r.headersOut["Set-Cookie"] = "auth_token=" + sessionId + "; " + r.variables.oidc_cookie_flags;
    r.return(302, r.variables.redirect_base + decodeURIComponent(r.variables.cookie_auth_redir));
}

// Extracts claims from token by calling the internal endpoint.
function getTokenClaims(r, token) {
    return new Promise((resolve, reject) => {
        r.subrequest('/_token_validation', 'token=' + token,
            function(reply) {
                if (reply.status !== 200) {
                    reject(new Error(`Failed to retrieve claims: HTTP ${reply.status}`));
                    return;
                }
                try {
                    const claims = JSON.parse(reply.responseText);
                    resolve(claims);
                } catch (e) {
                    reject(new Error(`Failed to parse claims: ${e}`));
                }
            }
        );
    });
}

// Extracts and validates claims from the ID Token.
async function validateIdToken(r, idToken) {
    const claims = await getTokenClaims(r, idToken);
    validateIdTokenClaims(r, claims);
    return claims;
}

// Validates the claims in the ID Token as per the OpenID Connect spec.
function validateIdTokenClaims(r, claims) {
    const requiredClaims = ["iat", "iss", "sub", "aud"];
    const missingClaims = requiredClaims.filter((claim) => !claims[claim]);

    if (missingClaims.length > 0) {
        throw new Error(
            `OIDC ID Token validation error: missing claim(s) ${missingClaims.join(' ')}`
        );
    }

    // Check 'iat' validity
    const iat = Math.floor(Number(claims.iat));
    if (String(iat) !== claims.iat || iat < 1) {
        throw new Error("OIDC ID Token validation error: iat claim is not a valid number");
    }

    // Audience must include the configured client
    const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        throw new Error(
            `OIDC ID Token validation error: aud claim (${claims.aud}) ` +
            `does not include $oidc_client (${r.variables.oidc_client})`
        );
    }

    // Nonce validation for initial authentication
    if (claims.nonce) {
        const clientNonceHash = r.variables.cookie_auth_nonce
            ? require('crypto')
                .createHmac('sha256', r.variables.oidc_hmac_key)
                .update(r.variables.cookie_auth_nonce)
                .digest('base64url')
            : '';

        if (claims.nonce !== clientNonceHash) {
            throw new Error(
                `OIDC ID Token validation error: nonce from token (${claims.nonce}) ` +
                `does not match client (${clientNonceHash})`
            );
        }
    } else if (isNewSession(r)) {
        throw new Error(
            "OIDC ID Token validation error: missing nonce claim during initial authentication."
        );
    }
}

// Store session data in the key-val store
function storeSessionData(r, sessionId, claims, tokenset, isNewSession) {
    if (claims.sid) {
        r.variables.idp_sid = claims.sid;
        r.variables.client_sid = sessionId;
    }

    if (isNewSession) {
        r.variables.new_session = tokenset.id_token;
        r.variables.new_access_token = tokenset.access_token || "";
        r.variables.new_refresh = tokenset.refresh_token || "";
    } else {
        r.variables.session_jwt = tokenset.id_token;
        r.variables.access_token = tokenset.access_token || "";
        if (tokenset.refresh_token && r.variables.refresh_token != tokenset.refresh_token) {
            r.variables.refresh_token = tokenset.refresh_token;
        }
    }
}

// Extracts claims from the validated ID Token (used by /_token_validation)
function extractTokenClaims(r) {
    const claims = {};
    const claimNames = ["sub", "iss", "iat", "nonce", "sid"];

    claimNames.forEach((name) => {
        const value = r.variables["jwt_claim_" + name];
        value && (claims[name] = value);
    });

    // Handle aud via 'jwt_audience' variable
    const audience = r.variables.jwt_audience;
    audience && (claims.aud = audience.split(","));

    r.return(200, JSON.stringify(claims));
}

// Determine the session ID depending on whether it's a new auth or a refresh
function getSessionId(r, isNewSession) {
    return isNewSession ? r.variables.request_id : r.variables.cookie_auth_token;
}

// Check for existing session using refresh token
function isNewSession(r) {
    return !r.variables.refresh_token || r.variables.refresh_token === '-';
}

// Exchange authorization code for tokens using the internal /_token endpoint
async function exchangeCodeForTokens(r) {
    let params;
    try {
        params = generateTokenRequestParams(r, "authorization_code");
    } catch (e) {
        oidcError(r, 500, getRefId(r, "token.params"), e);
        return null;
    }
    const reply = await new Promise((resolve) => {
        r.subrequest("/_token", params, resolve);
    });

    const ref = getRefId(r, "token.exchange");

    if (reply.status === 504) {
        oidcError(r, 504, ref, new Error("OIDC timeout connecting to IdP during code exchange"));
        return null;
    }

    if (reply.status !== 200) {
        let message;
        try {
            const errorset = JSON.parse(reply.responseText);
            if (errorset.error) {
                message = `OIDC error from IdP during token exchange: ${errorset.error}, ` +
                    `${errorset.error_description || ""}`;
            } else {
                message = `OIDC unexpected response from IdP (HTTP ${reply.status}). ` +
                    `${reply.responseText}`;
            }
        } catch (_e) {
            message = `OIDC unexpected response from IdP (HTTP ${reply.status}). ` +
                `${reply.responseText}`;
        }
        oidcError(r, 502, ref, new Error(message));
        return null;
    }

    try {
        const tokenset = JSON.parse(reply.responseText);
        if (tokenset.error) {
            oidcError(r, 500, ref,
                new Error(`OIDC token response error: ${tokenset.error}` +
                    ` ${tokenset.error_description}`)
            );
            return null;
        }
        return tokenset;
    } catch (_e) {
        oidcError(r, 502, ref, new Error(`OIDC token response not JSON: ${reply.responseText}`));
        return null;
    }
}

// Refresh tokens using the internal /_refresh endpoint
async function refreshTokens(r) {
    let params;
    try {
        params = generateTokenRequestParams(r, "refresh_token");
    } catch (e) {
        oidcError(r, 500, getRefId(r, "refresh.params"), e);
        return null;
    }
    const reply = await new Promise((resolve) => {
        r.subrequest("/_refresh", params, resolve);
    });

    if (reply.status !== 200) {
        handleRefreshError(r, reply);
        return null;
    }

    try {
        const tokenset = JSON.parse(reply.responseText);
        if (!tokenset.id_token) {
            r.log("OIDC refresh response did not include id_token" +
                (tokenset.error ? ("; " + tokenset.error + " " + tokenset.error_description) : ""));
            return null;
        }
        return tokenset;
    } catch (_e) {
        r.variables.refresh_token = "-";
        r.headersOut["Location"] = r.variables.request_uri;
        oidcError(r, 302, getRefId(r, "refresh.parse"), new Error("OIDC refresh response not JSON"));
        return null;
    }
}

// Logout handler
function logout(r) {
    r.log("OIDC RP-Initiated Logout for " + (r.variables.cookie_auth_token || "unknown"));

    function getLogoutRedirectUrl(base, redirect) {
        return redirect.match(/^(http|https):\/\//) ? redirect : base + redirect;
    }

    var logoutRedirectUrl = getLogoutRedirectUrl(r.variables.redirect_base,
        r.variables.oidc_logout_redirect);

    async function performLogout(redirectUrl, idToken) {
        // Clean up $idp_sid -> $client_sid mapping
        if (idToken && idToken !== '-') {
            try {
                const claims = await getTokenClaims(r, idToken);
                if (claims.sid) {
                    r.variables.idp_sid = claims.sid;
                    r.variables.client_sid = '-';
                }
            } catch (_e) {
            }
        }

        r.variables.session_jwt = '-';
        r.variables.access_token = '-';
        r.variables.refresh_token = '-';
        r.return(302, redirectUrl);
    }

    if (r.variables.oidc_end_session_endpoint) {
        // If no ID token but refresh token present, attempt to re-auth to get ID token
        if ((!r.variables.session_jwt || r.variables.session_jwt === '-')
            && r.variables.refresh_token && r.variables.refresh_token !== '-') {
            auth(r, 0);
        } else if (!r.variables.session_jwt || r.variables.session_jwt === '-') {
            performLogout(logoutRedirectUrl);
            return;
        }

        var logoutArgs = "?post_logout_redirect_uri=" + encodeURIComponent(logoutRedirectUrl) +
            "&id_token_hint=" + encodeURIComponent(r.variables.session_jwt);
        performLogout(r.variables.oidc_end_session_endpoint + logoutArgs, r.variables.session_jwt);
    } else {
        performLogout(logoutRedirectUrl, r.variables.session_jwt);
    }
}

/**
 * Handles Front-Channel Logout as per OpenID Connect Front-Channel Logout 1.0 spec.
 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html
 */
async function handleFrontChannelLogout(r) {
    const sid = r.args.sid;
    const requestIss = r.args.iss;

    // Validate input parameters
    if (!sid) {
        oidcError(r, 400, getRefId(r, "frontchannel.missingSid"),
            new Error("Missing sid parameter in front-channel logout request"));
        return;
    }

    if (!requestIss) {
        oidcError(r, 400, getRefId(r, "frontchannel.missingIss"),
            new Error("Missing iss parameter in front-channel logout request"));
        return;
    }

    r.log("OIDC Front-Channel Logout initiated for sid: " + sid);

    // Define idp_sid as a key to get the client_sid from the key-value store
    r.variables.idp_sid = sid;

    const clientSid = r.variables.client_sid;
    if (!clientSid || clientSid === '-') {
        r.log("No client session found for sid: " + sid);
        r.return(200, "Logout successful");
        return;
    }

    /* TODO: Since we cannot use the cookie_auth_token var as a key (it does not exist if cookies
       are absent), we use the request_id as a workaround. */
    r.variables.request_id = clientSid;
    var sessionJwt = r.variables.new_session;

    if (!sessionJwt || sessionJwt === '-') {
        r.log("No associated ID token found for client session: " + clientSid);
        cleanSessionData(r);
        r.return(200, "Logout successful");
        return;
    }

    let claims;
    try {
        claims = await getTokenClaims(r, sessionJwt);
    } catch (e) {
        oidcError(r, 400, getRefId(r, "frontchannel.claims"), e);
        return;
    }

    if (claims.iss !== requestIss) {
        oidcError(r, 400, getRefId(r, "frontchannel.issMismatch"),
            new Error(`Issuer mismatch during logout. ` +
                `Received iss: ${requestIss}, expected: ${claims.iss}`));
        return;
    }

    // idp_sid needs to be updated after subrequest
    r.variables.idp_sid = sid;
    cleanSessionData(r);

    r.return(200, "Logout successful");
}

function cleanSessionData(r) {
    r.variables.new_session = '-';
    r.variables.new_access_token = '-';
    r.variables.new_refresh = '-';
    r.variables.client_sid = '-';
}

// Initiate a new authentication flow by redirecting to the IdP's authorization endpoint
function initiateNewAuth(r) {
    const oidcConfigurables = ["authz_endpoint", "scopes", "hmac_key", "cookie_flags"];
    const missingConfig = oidcConfigurables.filter(key =>
        !r.variables["oidc_" + key] || r.variables["oidc_" + key] == ""
    );

    if (missingConfig.length) {
        oidcError(r, 500, getRefId(r, "init.missingConfig"),
            new Error(`OIDC missing configuration variables: $oidc_` +
                `${missingConfig.join(" $oidc_")}`)
        );
        return;
    }

    // Redirect to IdP authorization endpoint with the cookie set for state and nonce
    r.return(302, r.variables.oidc_authz_endpoint + getAuthZArgs(r));
}

// Generate the authorization request arguments
function getAuthZArgs(r) {
    var c = require('crypto');
    var noncePlain = r.variables.request_id;
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash = h.digest('base64url');

    var authZArgs = "?response_type=code&scope=" + r.variables.oidc_scopes +
        "&client_id=" + r.variables.oidc_client +
        "&redirect_uri=" + r.variables.redirect_base + r.variables.redir_location +
        "&nonce=" + nonceHash;

    if (r.variables.oidc_authz_extra_args) {
        authZArgs += "&" + r.variables.oidc_authz_extra_args;
    }

    var encodedRequestUri = encodeURIComponent(r.variables.request_uri);
    r.headersOut['Set-Cookie'] = [
        "auth_redir=" + encodedRequestUri + "; " + r.variables.oidc_cookie_flags,
        "auth_nonce=" + noncePlain + "; " + r.variables.oidc_cookie_flags
    ];

    if (r.variables.oidc_pkce_enable == 1) {
        var pkce_code_verifier = c.createHmac('sha256', r.variables.oidc_hmac_key)
            .update(String(Math.random())).digest('hex');
        r.variables.pkce_id = c.createHash('sha256')
            .update(String(Math.random())).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256')
            .update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += "&code_challenge_method=S256&code_challenge=" +
            pkce_code_challenge + "&state=" + r.variables.pkce_id;
    } else {
        authZArgs += "&state=0";
    }

    return authZArgs;
}

// Generate the token request parameters
function generateTokenRequestParams(r, grant_type) {
    var body = "grant_type=" + grant_type + "&client_id=" + r.variables.oidc_client;

    switch(grant_type) {
        case "authorization_code":
            body += "&code=" + r.variables.arg_code +
                "&redirect_uri=" + r.variables.redirect_base + r.variables.redir_location;
            if (r.variables.oidc_pkce_enable == 1) {
                r.variables.pkce_id = r.variables.arg_state;
                body += "&code_verifier=" + r.variables.pkce_code_verifier;
            }
            break;
        case "refresh_token":
            body += "&refresh_token=" + r.variables.refresh_token;
            break;
        default:
            throw new Error("Unsupported grant type: " + grant_type);
    }

    var options = {
        body: body,
        method: "POST"
    };

    if (r.variables.oidc_pkce_enable != 1) {
        if (r.variables.oidc_client_auth_method === "client_secret_basic") {
            let auth_basic = "Basic " + Buffer.from(r.variables.oidc_client + ":" +
                r.variables.oidc_client_secret).toString('base64');
            options.args = "secret_basic=" + auth_basic;
        } else {
            options.body += "&client_secret=" + r.variables.oidc_client_secret;
        }
    }

    return options;
}

// Handle refresh error: log + reset refresh + redirect 302 to original request
function handleRefreshError(r, reply) {
    const ref = getRefId(r, "refresh.error");
    let errorLog = "OIDC refresh failure";

    if (reply.status === 504) {
        errorLog += ", timeout waiting for IdP";
    } else if (reply.status === 400) {
        try {
            const errorset = JSON.parse(reply.responseText);
            errorLog += ": " + errorset.error + " " + errorset.error_description;
        } catch (_e) {
            errorLog += ": " + reply.responseText;
        }
    } else {
        errorLog += " " + reply.status;
    }

    r.variables.refresh_token = "-";
    r.headersOut["Location"] = r.variables.request_uri;
    oidcError(r, 302, ref, new Error(errorLog));
}

/* If the ID token has not been synced yet, poll the variable every 100ms until
    get a value or after a timeout. */
function waitForSessionSync(r, timeLeft) {
    if (r.variables.session_jwt) {
        retryOriginalRequest(r);
    } else if (timeLeft > 0) {
        setTimeout(waitForSessionSync, 100, r, timeLeft - 100);
    } else {
        auth(r, true);
    }
}

function retryOriginalRequest(r) {
    delete r.headersOut["WWW-Authenticate"];
    r.internalRedirect(r.variables.uri + r.variables.is_args + (r.variables.args || ''));
}

function oidcError(r, http_code, refId, e) {
    const hasDebug = !!r.variables.oidc_debug;
    const msg = (e && e.message) ? String(e.message) : (e ? String(e) : "Unexpected Error");
    const stack = (hasDebug && e && e.stack) ? String(e.stack) : "";

    const clientIp = r.remoteAddress || "-";
    const host = r.headersIn.host || r.variables.host || "-";
    const requestLine = `${r.method} ${r.uri} HTTP/${r.httpVersion}`;

    if (r.variables.oidc_log_format === "json") {
        const errorObj = {
            refId: refId,
            message: msg,
            clientIp: clientIp,
            host: host,
            method: r.method,
            uri: r.uri,
            httpVersion: r.httpVersion
        };
        if (stack) {
            errorObj.stack = stack;
        }
        r.error(JSON.stringify(errorObj));
    } else {
        let logEntry = `OIDC Error: ReferenceID: ${refId} ${msg}; ` +
            `client: ${clientIp}, host: ${host}, request: "${requestLine}"`;
        if (stack) {
            logEntry += `\n${stack}`;
        }
        r.error(logEntry);
    }

    if (hasDebug) {
        r.variables.internal_error_message = stack
            ? `ReferenceID: ${refId} ${msg}\n${stack}`
            : `ReferenceID: ${refId} ${msg}`;
    }

    r.return(http_code);
}

function getRefId(r, context) {
    const base = (r.variables.request_id).substring(0, 8);
    return context ? `${base}:${context}` : base;
}
