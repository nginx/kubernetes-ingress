# Keycloak Setup

This guide will help you configure KeyCloak using Keycloak's API:

- Create a `client` with the name `nginx-plus`.
- Add a user `nginx-user` with the password `test`.

**Notes**:

- This guide has been tested with keycloak 19.0.2 and later. If you modify `keycloak.yaml` to use an older version,
  Keycloak may not start correctly or the commands in this guide may not work as expected. The Keycloak OpenID
  endpoints `oidc.yaml` might also be different in older versions of Keycloak.
- if you changed the admin username and password for Keycloak in `keycloak.yaml`, modify the commands accordingly.
- The instructions use [`jq`](https://stedolan.github.io/jq/).

Steps:

1. Save the address of Keycloak into a shell variable:

    ```shell
    KEYCLOAK_ADDRESS=keycloak.example.com
    ```

2. Retrieve the access token and store it into a shell variable:

    ```shell
    TOKEN=`curl -sS -k --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" "https://${KEYCLOAK_ADDRESS}/realms/master/protocol/openid-connect/token" | jq -r .access_token`
    ```

   Ensure the request was successful and the token is stored in the shell variable by running:

   ```shell
   echo $TOKEN
   ```

   ***Note***: The access token lifespan is very short. If it expires between commands, retrieve it again with the
   command above.

3. Create the user `nginx-user`:

    ```shell
    curl -sS -k -X POST -d '{ "username": "nginx-user", "enabled": true, "credentials":[{"type": "password", "value": "test", "temporary": false}]}' -H "Content-Type:application/json" -H "Authorization: bearer ${TOKEN}" https://${KEYCLOAK_ADDRESS}/admin/realms/master/users
    ```

4. Create the client `nginx-plus`:

    - If you are not using PKCE, use the following command to create an OIDC client that does not use PKCE:

        ```shell
        SECRET=`curl -sS -k -X POST -d '{ "clientId": "nginx-plus", "redirectUris": ["https://webapp.example.com:443/_codexch"], "attributes": {"post.logout.redirect.uris": "https://webapp.example.com:443/*"}}' -H "Content-Type:application/json" -H "Authorization: bearer ${TOKEN}" https://${KEYCLOAK_ADDRESS}/realms/master/clients-registrations/default | jq -r .secret`
        ```

        If everything went well, you should have the secret stored in $SECRET. To double-check, run:

        ```shell
        echo $SECRET
        ```

    - Or if you are using PKCE with OIDC, use the following command to create the client:

        ```shell
        curl -sS -k -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" \
        --data '{
            "clientId": "nginx-plus",
            "enabled": true,
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": false,
            "publicClient": true,
            "redirectUris": [
                "https://webapp.example.com:443/_codexch"
            ],
            "attributes": {
                "pkce.code.challenge.method":"S256",
                "post.logout.redirect.uris": "https://webapp.example.com:443/*"
            },
            "protocol": "openid-connect"
        }' \
        https://${KEYCLOAK_ADDRESS}/admin/realms/master/clients
        ```
