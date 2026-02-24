# Runtime Management

In addition to configuring users and clients through configuration files or environment variables, you can also create and manage them at runtime through the web interface.

## Managing Users

Navigate to `/users` to access the user management interface.

### Creating Users

1. Fill in the following fields:
   - **Email**: The email address of the user
   - **First Name**: The user's first name
   - **Last Name**: The user's last name
   - **Roles** (Optional): Comma-separated list of roles to assign to the user

2. Click "Create User"

Users created at runtime are immediately available for login. You can select them from the login dropdown to authenticate.

### Assigning Roles

You can assign one or more roles to a user:

- **Select existing roles**: Enter role names that already exist in the system
- **Create new roles**: Enter new role names that will be created automatically if they don't exist
- **Multiple roles**: Separate multiple role names with commas, e.g., `admin, moderator, viewer`

Roles are included in the OIDC tokens issued for users, allowing applications to check user permissions.

## Managing Clients

Navigate to `/clients` to access the client (OIDC application) management interface.

### Creating Clients

1. Fill in the following fields:
   - **Client ID**: A unique identifier for the client
   - **Client Secret**: A secret string shared between the client and the identity provider
   - **Redirect URIs** (Optional): Comma-separated list of URIs where the user will be redirected after authentication
   - **Post-Logout Redirect URIs** (Optional): Comma-separated list of URIs where the user will be redirected after logout

2. Click "Create Client"

Newly created clients are immediately available and can be used for OpenID Connect flows.

### Configuring Redirect URIs

Both redirect URIs and post-logout redirect URIs should be valid, complete URLs:

```
http://localhost:3000/callback, https://example.com/oauth/callback
```

URIs are validated on submission to ensure they are properly formatted.

## Important Notes

- **No Persistence**: Users and clients created at runtime exist only in the in-memory database. They will be lost when the application restarts.
- **Configuration + Runtime**: You can use both configuration-based users/clients and runtime-created ones simultaneously.
- **Role Management**: Roles created at runtime persist for the lifetime of the application and can be assigned to multiple users.
