# Setting Up Keycloak for Native OIDC

This document describes how to configure Keycloak for use with NGINX Ingress Controller Native OIDC.

## Prerequisites

1. Deploy Keycloak:

    ```shell
    kubectl apply -f keycloak.yaml
    kubectl apply -f keycloak-ingress.yaml
    ```

2. Get the external IP or domain of your Ingress Controller and store it in environment variables:

    ```shell
    export KEYCLOAK_HOST=keycloak.<EXTERNAL-IP>.nip.io
    export WEBAPP_HOST=webapp.<EXTERNAL-IP>.nip.io
    ```

## Automated Setup via Keycloak REST API

Run the following commands to configure Keycloak automatically:

1. Obtain an admin token:

    ```shell
    TOKEN=`curl -sS -k --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" "https://${KEYCLOAK_HOST}/realms/master/protocol/openid-connect/token" | jq -r .access_token`
    ```

2. Create a test user `nginx-user`:

    ```shell
    curl -sS -k -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d '{"username": "nginx-user", "enabled": true, "credentials": [{"type": "password", "value": "test", "temporary": false}]}' \
        "https://${KEYCLOAK_HOST}/admin/realms/master/users"
    ```

3. Register the OIDC client `nginx-plus`:

    ```shell
    curl -sS -k -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d "{
            \"clientId\": \"nginx-plus\",
            \"secret\": \"oEJ3QhcKVYR42eZ5soWLeasGzQj7gYwGSBQa3sDZBoaxu4Up9wsgneF4AuFu6OnaxfROwXL5X4HEeY9Xyq4XkV\",
            \"directAccessGrantsEnabled\": true,
            \"redirectUris\": [\"https://${WEBAPP_HOST}/*\"]
        }" \
        "https://${KEYCLOAK_HOST}/realms/master/clients-registrations/default"
    ```

## Manual Setup via Keycloak Console

Alternatively, configure Keycloak manually via the web UI:

1. Open `https://${KEYCLOAK_HOST}` in your browser and log in with `admin` / `admin`.
2. Go to **Users** -> **Add user**.
   - Username: `nginx-user`
   - Toggle **Enabled** to On.
   - Save, then go to the **Credentials** tab and set the password to `test` (toggle Temporary to Off).
3. Go to **Clients** -> **Create client**.
   - Client ID: `nginx-plus`
   - Client authentication: On
   - Valid redirect URIs: `https://${WEBAPP_HOST}/*`
   - Save, then go to the **Credentials** tab, copy the **Client Secret**, and put it in `client-secret.yaml`.
