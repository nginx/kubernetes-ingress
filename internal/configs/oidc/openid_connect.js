/*
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 *
 * Copyright (C) 2020 Nginx, Inc.
 */
export default {auth, codeExchange, validateIdToken, logout};

function retryOriginalRequest(r) {
    delete r.headersOut["WWW-Authenticate"]; // Remove evidence of original failed auth_jwt
    r.internalRedirect(r.variables.uri + r.variables.is_args + (r.variables.args || ''));
}

// If the ID token has not been synced yet, poll the variable every 100ms until
// get a value or after a timeout.
function waitForSessionSync(r, timeLeft) {
    if (r.variables.session_jwt) {
        retryOriginalRequest(r);
    } else if (timeLeft > 0) {
        setTimeout(waitForSessionSync, 100, r, timeLeft - 100);
    } else {
        auth(r, true);
    }
}

function auth(r, afterSyncCheck) {
    // If a cookie was sent but the ID token is not in the key-value database, wait for the token to be in sync.
    if (r.variables.cookie_auth_token && !r.variables.session_jwt && !afterSyncCheck && r.variables.zone_sync_leeway > 0) {
        waitForSessionSync(r, r.variables.zone_sync_leeway);
        return;
    }

    if (!r.variables.refresh_token || r.variables.refresh_token == "-") {
        // Check we have all necessary configuration variables (referenced only by njs)
        var oidcConfigurables = ["authz_endpoint", "scopes", "hmac_key", "cookie_flags"];
        var missingConfig = [];
        for (var i in oidcConfigurables) {
            if (!r.variables["oidc_" + oidcConfigurables[i]] || r.variables["oidc_" + oidcConfigurables[i]] == "") {
                missingConfig.push(oidcConfigurables[i]);
            }
        }
        if (missingConfig.length) {
            r.error("OIDC missing configuration variables: $oidc_" + missingConfig.join(" $oidc_"));
            r.return(500, r.variables.internal_error_message);
            return;
        }
        // Redirect the client to the IdP login page with the cookies we need for state
        r.return(302, r.variables.oidc_authz_endpoint + getAuthZArgs(r));
        return;
    }

    // Pass the refresh token to the /_refresh location so that it can be
    // proxied to the IdP in exchange for a new id_token
    r.subrequest("/_refresh", generateTokenRequestParams(r, "refresh_token"),
        function(reply) {
            if (reply.status != 200) {
                // Refresh request failed, log the reason
                var error_log = "OIDC refresh failure";
                if (reply.status == 504) {
                    error_log += ", timeout waiting for IdP";
                } else if (reply.status == 400) {
                    try {
                        var errorset = JSON.parse(reply.responseText);
                        error_log += ": " + errorset.error + " " + errorset.error_description;
                    } catch (e) {
                        error_log += ": " + reply.responseText;
                    }
                } else {
                    error_log += " "  + reply.status;
                }
                r.error(error_log);

                // Clear the refresh token, try again
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }

            // Refresh request returned 200, check response
            try {
                var tokenset = JSON.parse(reply.responseText);
                if (!tokenset.id_token) {
                    r.error("OIDC refresh response did not include id_token");
                    if (tokenset.error) {
                        r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    }
                    r.variables.refresh_token = "-";
                    r.return(302, r.variables.request_uri);
                    return;
                }

                // Send the new ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.variables.refresh_token = "-";
                            r.return(302, r.variables.request_uri);
                            return;
                        }

                        // ID Token is valid, update keyval
                        r.log("OIDC refresh success, updating id_token for " + r.variables.cookie_auth_token);
                        r.variables.session_jwt = tokenset.id_token; // Update key-value store
                        if (tokenset.access_token) {
                            r.variables.access_token = tokenset.access_token;
                        } else {
                            r.variables.access_token = "";
                        }

                        // Update refresh token (if we got a new one)
                        if (r.variables.refresh_token != tokenset.refresh_token) {
                            r.log("OIDC replacing previous refresh token (" + r.variables.refresh_token + ") with new value: " + tokenset.refresh_token);
                            r.variables.refresh_token = tokenset.refresh_token; // Update key-value store
                        }

                        retryOriginalRequest(r); // Continue processing original request
                    }
                );
            } catch (e) {
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }
        }
    );
}

function codeExchange(r) {
    // First check that we received an authorization code from the IdP
    if (r.variables.arg_code == undefined || r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code from IdP: " + r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code from IdP but received: " + r.uri);
        }
        r.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    r.subrequest("/_token", generateTokenRequestParams(r, "authorization_code"), function(reply) {
            if (reply.status == 504) {
                r.error("OIDC timeout connecting to IdP when sending authorization code");
                r.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.responseText);
                    if (errorset.error) {
                        r.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseText);
                    }
                } catch (e) {
                    r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseText);
                }
                r.return(502);
                return;
            }

            // Code exchange returned 200, check for errors
            try {
                var tokenset = JSON.parse(reply.responseText);
                if (tokenset.error) {
                    r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    r.return(500);
                    return;
                }

                // Send the ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.return(500); // validateIdToken() will log errors
                            return;
                        }

                        // If the response includes a refresh token then store it
                        if (tokenset.refresh_token) {
                            r.variables.new_refresh = tokenset.refresh_token; // Create key-value store entry
                            r.log("OIDC refresh token stored");
                        } else {
                            r.warn("OIDC no refresh token");
                        }

                        // Add opaque token to keyval session store
                        r.log("OIDC success, creating session " + r.variables.request_id);
                        r.variables.new_session = tokenset.id_token; // Create key-value store entry
                        if (tokenset.access_token) {
                            r.variables.new_access_token = tokenset.access_token;
                        } else {
                            r.variables.new_access_token = "";
                        }

                        r.headersOut["Set-Cookie"] = "auth_token=" + r.variables.request_id + "; " + r.variables.oidc_cookie_flags;
                        r.return(302, r.variables.redirect_base + decodeURIComponent(r.variables.cookie_auth_redir));
                   }
                );
            } catch (e) {
                r.error("OIDC authorization code sent but token response is not JSON. " + reply.responseText);
                r.return(502);
            }
        }
    );
}

function validateIdToken(r) {
    // Check mandatory claims
    var required_claims = ["iat", "iss", "sub"]; // aud is checked separately
    var missing_claims = [];
    for (var i in required_claims) {
        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (r.variables.jwt_audience.length == 0) missing_claims.push("aud");
    if (missing_claims.length) {
        r.error("OIDC ID Token validation error: missing claim(s) " + missing_claims.join(" "));
        r.return(403);
        return;
    }
    var validToken = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error("OIDC ID Token validation error: iat claim is not a valid number");
        validToken = false;
    }

    // Audience matching
    var aud = r.variables.jwt_audience.split(",");
    if (!aud.includes(r.variables.oidc_client)) {
        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_audience + ") does not include configured $oidc_client (" + r.variables.oidc_client + ")");
        validToken = false;
    }

    // According to OIDC Core 1.0 Section 2:
    // "If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request."
    if (r.variables.jwt_claim_nonce) {
        var client_nonce_hash = "";
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
            client_nonce_hash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != client_nonce_hash) {
            r.error("OIDC ID Token validation error: nonce from token (" + r.variables.jwt_claim_nonce + ") does not match client (" + client_nonce_hash + ")");
            validToken = false;
        }
    } else if (!r.variables.refresh_token || r.variables.refresh_token == "-") {
        r.error("OIDC ID Token validation error: missing nonce claim in ID Token during initial authentication.");
        validToken = false;
    }

    if (validToken) {
        r.return(204);
    } else {
        r.return(403);
    }
}

function logout(r) {
    r.log("OIDC logout for " + r.variables.cookie_auth_token);

    // Determine if oidc_logout_redirect is a full URL or a relative path
    function getLogoutRedirectUrl(base, redirect) {
        return redirect.match(/^(http|https):\/\//) ? redirect : base + redirect;
    }

    var logoutRedirectUrl = getLogoutRedirectUrl(r.variables.redirect_base, r.variables.oidc_logout_redirect);

    // Helper function to perform the final logout steps
    function performLogout(redirectUrl) {
        r.variables.session_jwt = '-';
        r.variables.access_token = '-';
        r.variables.refresh_token = '-';
        r.return(302, redirectUrl);
    }

    // Check if OIDC end session endpoint is available
    if (r.variables.oidc_end_session_endpoint) {

        if (!r.variables.session_jwt || r.variables.session_jwt === '-') {
            if (r.variables.refresh_token && r.variables.refresh_token !== '-') {
                // Renew ID token if only refresh token is available
                auth(r, 0);
            } else {
                performLogout(logoutRedirectUrl);
                return;
            }
        }

        // Construct logout arguments for RP-initiated logout
        var logoutArgs = "?post_logout_redirect_uri=" + encodeURIComponent(logoutRedirectUrl) +
                         "&id_token_hint=" + encodeURIComponent(r.variables.session_jwt);
        performLogout(r.variables.oidc_end_session_endpoint + logoutArgs);
    } else {
        // Fallback to traditional logout approach
        performLogout(logoutRedirectUrl);
    }
}

function getAuthZArgs(r) {
    // Choose a nonce for this flow for the client, and hash it for the IdP
    var noncePlain = r.variables.request_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash = h.digest('base64url');
    var authZArgs = "?response_type=code&scope=" + r.variables.oidc_scopes + "&client_id=" + r.variables.oidc_client + "&redirect_uri="+ r.variables.redirect_base + r.variables.redir_location + "&nonce=" + nonceHash;

    if (r.variables.oidc_authz_extra_args) {
        authZArgs += "&" + r.variables.oidc_authz_extra_args;
    }

    var encodedRequestUri = encodeURIComponent(r.variables.request_uri);

    r.headersOut['Set-Cookie'] = [
        "auth_redir=" + encodedRequestUri + "; " + r.variables.oidc_cookie_flags,
        "auth_nonce=" + noncePlain + "; " + r.variables.oidc_cookie_flags
    ];

    if ( r.variables.oidc_pkce_enable == 1 ) {
        var pkce_code_verifier = c.createHmac('sha256', r.variables.oidc_hmac_key).update(String(Math.random())).digest('hex');
        r.variables.pkce_id = c.createHash('sha256').update(String(Math.random())).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += "&code_challenge_method=S256&code_challenge=" + pkce_code_challenge + "&state=" + r.variables.pkce_id;
    } else {
        authZArgs += "&state=0";
    }
    return authZArgs;
}

function generateTokenRequestParams(r, grant_type) {
    var body = "grant_type=" + grant_type + "&client_id=" + r.variables.oidc_client;

    switch(grant_type) {
        case "authorization_code":
            body += "&code=" + r.variables.arg_code + "&redirect_uri=" + r.variables.redirect_base + r.variables.redir_location;
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
            let auth_basic = "Basic " + Buffer.from(r.variables.oidc_client + ":" + r.variables.oidc_client_secret).toString('base64');
            options.args = "secret_basic=" + auth_basic;
        } else {
            options.body += "&client_secret=" + r.variables.oidc_client_secret;
        }
    }

    return options;
}
