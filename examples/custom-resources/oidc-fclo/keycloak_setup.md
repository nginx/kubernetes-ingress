# Keycloak Setup for Front Channel Logout example

This guide will help you configure KeyCloak using its administration dashboard:

- Create two `client`s with IDs `fclo-one` and `fclo-two`.
- Add a user `nginx-user` with the password `test`.

**Notes**:

- This guide has been tested with keycloak 26.4 and later. If you modify `keycloak.yaml` to use an older version,
  Keycloak may not start correctly or the commands in this guide may not work as expected. The Keycloak OpenID
  endpoints in `oidc-one.yaml` and `oidc-two.yaml` might also be different in older versions of Keycloak.
- if you changed the admin username and password for Keycloak in `keycloak.yaml`, modify the commands accordingly.

Steps:

1. Make sure that you can reach the Keycloak admin page by going to <https://keycloak.example.com>
2. Log in with the admin username and password that's in the `keycloak.yaml` file
3. Create the user `nginx-user` by clicking the Users menu on the left sidebar, and then the Add User button
   1. Set "email verified" to be true, enter username as `nginx-user`, and click Create
   2. After you created the user, click the Credentials tab (second from the left), and click Set Password button
   3. Enter a password, and make sure the Temporary toggle is turned off. Click Save, then click the red Save Password prompt
4. Create the two clients. Start by clicking the Client menu option on the sidebar on the left
5. For each of the clients
   1. Click the blue Create Client button
   2. Enter a new Client ID: either `fclo-one` or `fclo-two`. These are important, as the yaml files refer to the clients by them
   3. Enter a name so they show up on a logout page, this can be anything you choose, as long as it's not empty
   4. Make sure the Always Display in UI toggle is turned on
   5. Click Next
   6. Set Client Authentication to be "On"
   7. Click Next
   8. For root and home urls, enter `https://fclo-one.example.com`. Adjust to `fclo-two` for the other one
   9. As valid redirect URIs, enter `https://fclo-one.example.com:443/*`. Both the port and the asterisk are important. Adjust to `fclo-two` for the other one
   10. Click Save
   11. Scroll down to the bottom to the Front Channel Logout section
   12. Enter the front channel logout url: `https://fclo-one.example.com/front_channel_logout`. Adjust to `fclo-two` for the other client
   13. Click save
   14. Click on the Credentials tab at the top, and copy the Client Secret
   15. In your terminal, base64 encode that secret with the following command: `echo -n "<secret>" | base64`
   16. Copy the result into the `client-secret-one.yaml` file or `client-secret-two.yaml` file
