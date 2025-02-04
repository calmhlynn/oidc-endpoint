# API Gateway

This project is a REST API server implementing OpenID Connect (OIDC) with a Keycloak server as the base. It provides secure authentication and authorization for your applications.

## Features

- OIDC authentication with Keycloak
- Session management
- Token handling

## Environment Setup

The following environment variables are required to configure the server:

- `KEYCLOAK_AUTH_SERVER_URL`: The URL of the Keycloak authentication server.
- `KEYCLOAK_REALM`: The Keycloak realm to use.
- `KEYCLOAK_CLIENT_ID`: The client ID for Keycloak.
- `KEYCLOAK_CLIENT_SECRET`: The client secret for Keycloak.
- `CALLBACK_URL`: The callback URL for authentication.
- `REDIS_URL`: The URL for the Redis server.

Ensure that a Redis server is running and accessible at the specified `REDIS_URL`.

## License

This project is licensed under the MIT License.

