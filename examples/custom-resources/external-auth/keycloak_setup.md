# Keycloak Setup

This guide will help you configure Keycloak using Keycloak's API:

- Create a `client` with the name `nginx-plus`.
- Add a user `nginx-user` with the password `test`.

**Notes**:

- This guide has been tested with Keycloak 26.5.3 and later. If you modify `keycloak.yaml` to use an older version,
  Keycloak may not start correctly or the commands in this guide may not work as expected.
- If you changed the admin username and password for Keycloak in `keycloak.yaml`, modify the commands accordingly.
- The instructions use [`jq`](https://stedolan.github.io/jq/).

## Steps

1. Save the address of Keycloak into a shell variable:

    ```shell
    KEYCLOAK_ADDRESS=keycloak.example.com
    ```

2. Retrieve the access token and store it into a shell variable:

    ```shell
    TOKEN=$(curl -sS -k --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
      "https://${KEYCLOAK_ADDRESS}/realms/master/protocol/openid-connect/token" | jq -r .access_token)
    ```

   Ensure the request was successful and the token is stored in the shell variable by running:

   ```shell
   echo $TOKEN
   ```

   ***Note***: The access token lifespan is very short. If it expires between commands, retrieve it again with the
   command above.

3. Create the user `nginx-user`:

    ```shell
    curl -sS -k -X POST \
      -d '{ "username": "nginx-user", "enabled": true, "credentials":[{"type": "password", "value": "test", "temporary": false}]}' \
      -H "Content-Type:application/json" \
      -H "Authorization: bearer ${TOKEN}" \
      "https://${KEYCLOAK_ADDRESS}/admin/realms/master/users"
    ```

4. Create the client `nginx-plus`:

    ```shell
    SECRET=$(curl -sS -k -X POST \
      -d '{ "clientId": "nginx-plus", "redirectUris": ["https://cafe.example.com:443/_oauth2/callback"]}' \
      -H "Content-Type:application/json" \
      -H "Authorization: bearer ${TOKEN}" \
      "https://${KEYCLOAK_ADDRESS}/realms/master/clients-registrations/default" | jq -r .secret)
    ```

    If everything went well, you should have the secret stored in `$SECRET`. To double-check, run:

    ```shell
    echo $SECRET
    ```

5. Base64-encode the secret and update `oauth2-proxy-client-secret.yaml`:

    ```shell
    echo -n "$SECRET" | base64
    ```

    Replace the `client-secret` value in `oauth2-proxy-client-secret.yaml` with the base64-encoded output.
