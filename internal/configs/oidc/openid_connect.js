/*
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 *
 * Copyright (C) 2024 Nginx, Inc.
 */

export default {
    auth,
    codeExchange,
    extractTokenClaims,
    logout
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
    const claims = await validateIdToken(r, tokenset.id_token);
    if (!claims) {
        // If validation failed, reset and reinitiate auth
        r.variables.refresh_token = "-";
        r.return(302, r.variables.request_uri);
        return;
    }

    // Determine session ID and store session data
    const sessionId = getSessionId(r, false);
    storeSessionData(r, tokenset, false);

    r.log("OIDC success, refreshing session " + sessionId);

    // Continue processing original request
    retryOriginalRequest(r);
}

// The code exchange handler, called after IdP redirects back with a authorization code.
async function codeExchange(r) {
    // Check authorization code presence
    if (!r.variables.arg_code || r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code: " +
                    r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code but received: " + r.uri);
        }
        r.return(502);
        return;
    }

    // Exchange authorization code for tokens
    const tokenset = await exchangeCodeForTokens(r);
    if (!tokenset) {
        return;
    }

    // Validate ID token
    const claims = await validateIdToken(r, tokenset.id_token);
    if (!claims) {
        r.return(500);
        return;
    }

    // Determine session ID and store session data for a new session
    const sessionId = getSessionId(r, true);
    storeSessionData(r, tokenset, true);

    r.log("OIDC success, creating session " + sessionId);

    // Set cookie and redirect to the originally requested URI
    r.headersOut["Set-Cookie"] = "auth_token=" + sessionId + "; " + r.variables.oidc_cookie_flags;
    r.return(302, r.variables.redirect_base + decodeURIComponent(r.variables.cookie_auth_redir));
}

// Extracts claims from token by calling the internal endpoint.
function getTokenClaims(r, token) {
    return new Promise((resolve) => {
        r.subrequest('/_token_validation', 'token=' + token,
            function(reply) {
                if (reply.status !== 200) {
                    r.error("Failed to retrieve claims: HTTP " + reply.status);
                    resolve(null);
                    return;
                }
                try {
                    const claims = JSON.parse(reply.responseText);
                    resolve(claims);
                } catch (e) {
                    r.error("Failed to parse claims: " + e);
                    resolve(null);
                }
            }
        );
    });
}

// Extracts and validates claims from the ID Token.
async function validateIdToken(r, idToken) {
    const claims = await getTokenClaims(r, idToken);
    if (!claims) {
        return null;
    }

    if (!validateIdTokenClaims(r, claims)) {
        return null;
    }

    return claims;
}

// Validates the claims in the ID Token as per the OpenID Connect spec.
function validateIdTokenClaims(r, claims) {
    const requiredClaims = ["iat", "iss", "sub", "aud"];
    const missingClaims = requiredClaims.filter((claim) => !claims[claim]);

    if (missingClaims.length > 0) {
        r.error(`OIDC ID Token validation error: missing claim(s) ${missingClaims.join(' ')}`);
        return false;
    }

    // Check 'iat' validity
    const iat = Math.floor(Number(claims.iat));
    if (String(iat) !== claims.iat || iat < 1) {
        r.error("OIDC ID Token validation error: iat claim is not a valid number");
        return false;
    }

    // Audience must include the configured client
    const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        r.error(`OIDC ID Token validation error: aud claim (${claims.aud}) ` +
                `does not include $oidc_client (${r.variables.oidc_client})`);
        return false;
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
            r.error(`OIDC ID Token validation error: nonce from token (${claims.nonce}) ` +
                    `does not match client (${clientNonceHash})`);
            return false;
        }
    } else if (isNewSession(r)) {
        r.error("OIDC ID Token validation error: " +
                "missing nonce claim during initial authentication.");
        return false;
    }

    return true;
}

// Store session data in the key-val store
function storeSessionData(r, tokenset, isNewSession) {
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
    const claimNames = ["sub", "iss", "iat", "nonce"];

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
    const reply = await new Promise((resolve) => {
        r.subrequest("/_token", generateTokenRequestParams(r, "authorization_code"), resolve);
    });

    if (reply.status === 504) {
        r.error("OIDC timeout connecting to IdP during code exchange");
        r.return(504);
        return null;
    }

    if (reply.status !== 200) {
        handleTokenError(r, reply);
        r.return(502);
        return null;
    }

    try {
        const tokenset = JSON.parse(reply.responseText);
        if (tokenset.error) {
            r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
            r.return(500);
            return null;
        }
        return tokenset;
    } catch (e) {
        r.error("OIDC token response not JSON: " + reply.responseText);
        r.return(502);
        return null;
    }
}

// Refresh tokens using the internal /_refresh endpoint
async function refreshTokens(r) {
    const reply = await new Promise((resolve) => {
        r.subrequest("/_refresh", generateTokenRequestParams(r, "refresh_token"), resolve);
    });

    if (reply.status !== 200) {
        handleRefreshError(r, reply);
        return null;
    }

    try {
        const tokenset = JSON.parse(reply.responseText);
        if (!tokenset.id_token) {
            r.error("OIDC refresh response did not include id_token");
            if (tokenset.error) {
                r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
            }
            return null;
        }
        return tokenset;
    } catch (e) {
        r.variables.refresh_token = "-";
        r.return(302, r.variables.request_uri);
        return null;
    }
}

// Logout handler
function logout(r) {
    r.log("RP-Initiated Logout for " + (r.variables.cookie_auth_token || "unknown"));

    function getLogoutRedirectUrl(base, redirect) {
        return redirect.match(/^(http|https):\/\//) ? redirect : base + redirect;
    }

    var logoutRedirectUrl = getLogoutRedirectUrl(r.variables.redirect_base,
                            r.variables.oidc_logout_redirect);

    function performLogout(redirectUrl) {
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
        performLogout(r.variables.oidc_end_session_endpoint + logoutArgs);
    } else {
        performLogout(logoutRedirectUrl);
    }
}

// Initiate a new authentication flow by redirecting to the IdP's authorization endpoint
function initiateNewAuth(r) {
    const oidcConfigurables = ["authz_endpoint", "scopes", "hmac_key", "cookie_flags"];
    const missingConfig = oidcConfigurables.filter(key =>
        !r.variables["oidc_" + key] || r.variables["oidc_" + key] == ""
    );

    if (missingConfig.length) {
        r.error("OIDC missing configuration variables: $oidc_" + missingConfig.join(" $oidc_"));
        r.return(500, r.variables.internal_error_message);
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
            r.error("Unsupported grant type: " + grant_type);
            return;
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

function handleTokenError(r, reply) {
    try {
        const errorset = JSON.parse(reply.responseText);
        if (errorset.error) {
            r.error("OIDC error from IdP during token exchange: " +
                    errorset.error + ", " + errorset.error_description);
        } else {
            r.error("OIDC unexpected response from IdP (HTTP " +
                    reply.status + "). " + reply.responseText);
        }
    } catch (e) {
        r.error("OIDC unexpected response from IdP (HTTP " + reply.status + "). " +
                reply.responseText);
    }
}


function handleRefreshError(r, reply) {
    let errorLog = "OIDC refresh failure";
    if (reply.status === 504) {
        errorLog += ", timeout waiting for IdP";
    } else if (reply.status === 400) {
        try {
            const errorset = JSON.parse(reply.responseText);
            errorLog += ": " + errorset.error + " " + errorset.error_description;
        } catch (e) {
            errorLog += ": " + reply.responseText;
        }
    } else {
        errorLog += " " + reply.status;
    }
    r.error(errorLog);
    r.variables.refresh_token = "-";
    r.return(302, r.variables.request_uri);
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
