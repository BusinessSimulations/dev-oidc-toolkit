# Configuration

Dev OIDC Toolkit can be configured in two ways, either through environment variables, or through a JSON configuration
file.

## Environment variable configuration

Dev OIDC Toolkit can be configured using environment variables. The environment variables should be prefixed with
`DevOidcToolkit__`.

### Docker

Here is how to run the application in a Docker container with environment variables:

```bash
docker run -p 8080:8080                                                               \
    -e DevOidcToolkit__Users__0__Email=test@localhost                                 \
    -e DevOidcToolkit__Users__0__FirstName=Test                                       \
    -e DevOidcToolkit__Users__0__LastName=User                                        \
    -e DevOidcToolkit__Clients__0__Id=client                                          \
    -e DevOidcToolkit__Clients__0__Secret=secret                                      \
    -e DevOidcToolkit__Clients__0__RedirectUris__INDEX=http://localhost:3000/callback \
    ghcr.io/businesssimulations/dev-oidc-toolkit
```

The `__0__` refers to the index of the user or client, and can be any integer, this allows you to add more users or
clients by increasing the index.

### Reference

This is a list of all of the environment variables that can be used to configure Dev OIDC Toolkit.

<table>
    <thead>
        <tr>
            <th>Environment Variable</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>DevOidcToolkit__Port</td>
            <td>The port that the application will listen on.</td>
            <td>80</td>
            <td>80</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Address</td>
            <td>The address that the application will listen on.</td>
            <td>localhost</td>
            <td>localhost</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Logging__MinimumLevel</td>
            <td>The minimum log level, possible values are Trace, Debug, Information, Warning, Error, Critical.</td>
            <td>Information</td>
            <td>Information</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Logging__UseXForwardedForHeader</td>
            <td>Whether to use the X-Forwarded-For header, useful if behind a proxy.</td>
            <td>false</td>
            <td>false</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Https_File_CertificatePath</td>
            <td>The path to the certificate file.</td>
            <td>/app/cert.pem</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Https_File_PrivateKeyPath</td>
            <td>The path to the private key file.</td>
            <td>/app/key.pem</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Https_Inline_Certificate</td>
            <td>The certificate as a string.</td>
            <td>Raw PEM certificate</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Https_Inline_PrivateKey</td>
            <td>The private key as a string.</td>
            <td>Raw PEM private key</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Users__INDEX__Email</td>
            <td>The email of the user.</td>
            <td>user@example.com</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Users__INDEX__FirstName</td>
            <td>The first name of the user.</td>
            <td>John</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Users__INDEX__LastName</td>
            <td>The last name of the user.</td>
            <td>Doe</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Clients__INDEX__Id</td>
            <td>The ID of the client.</td>
            <td>client</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Clients__INDEX__Secret</td>
            <td>The secret of the client.</td>
            <td>client</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Clients__INDEX__RedirectUris__INDEX</td>
            <td>The redirect URIs of the client.</td>
            <td>http://localhost:8080/callback</td>
            <td>None</td>
        </tr>
        <tr>
            <td>DevOidcToolkit__Clients__INDEX__PostLogoutRedirectUris__INDEX</td>
            <td>The post logout redirect URIs of the client.</td>
            <td>http://localhost:8080/callback</td>
            <td>None</td>
        </tr>
    </tbody>
</table>


## File configuration

Dev OIDC Toolkit can be configured using a JSON file. The file should be named `config.json` and should be placed in
the same directory that the application is running in.

### Docker

When running the application in a Docker container, the `config.json` file should be mounted to the container at
`/app/config.json`.

Here is how to run the application in a Docker container with a configuration file mounted:

```bash
docker run -p 8080:8080 -v ./config.json:/app/config.json ghcr.io/businesssimulations/dev-oidc-toolkit
```

### Reference

This is a list of all of the JSON properties that can be used to configure Dev OIDC Toolkit.

All properties are included in a JSON object with the key `DevOidcToolkit` (see the [example for more
details](#example-json-configuration)).

#### Root

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Port</td>
            <td>int</td>
            <td>The port that the application will listen on.</td>
            <td>80</td>
            <td>80</td>
        </tr>
        <tr>
            <td>Address</td>
            <td>string</td>
            <td>The address that the application will listen on.</td>
            <td>localhost</td>
            <td>localhost</td>
        </tr>
        <tr>
            <td>Https</td>
            <td>object</td>
            <td>The HTTPS configuration, see <a href="#https">HTTPS</a> for more information.</td>
            <td>See <a href="#https">HTTPS</a> for more information.</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Logging</td>
            <td>object</td>
            <td>The logging configuration, see <a href="#logging">Logging</a> for more information.</td>
            <td>See <a href="#logging">Logging</a> for more information.</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Users</td>
            <td>array</td>
            <td>The users that will be created in the database, see <a href="#users">Users</a> for more information.</td>
            <td>See <a href="#users">Users</a> for more information.</td>
            <td>[]</td>
        </tr>
        <tr>
            <td>Clients</td>
            <td>array</td>
            <td>The clients that will be created in the database, see <a href="#clients">Clients</a> for more information.</td>
            <td>See <a href="#clients">Clients</a> for more information.</td>
            <td>[]</td>
        </tr>
    </tbody>
</table>

#### Https

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>File</td>
            <td>object</td>
            <td>The HTTPS configuration, see <a href="#https-file-certificate">HTTPS file certificate</a> for more information.</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Inline</td>
            <td>object</td>
            <td>The HTTPS configuration, see <a href="#https-inline-certificate">HTTPS inline certificate</a> for more information.</td>
            <td>None</td>
        </tr>
    </tbody>
</table>

#### Https file certificate

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>CertificatePath</td>
            <td>string</td>
            <td>The path to the certificate file.</td>
            <td>/app/cert.pem</td>
            <td>None</td>
        </tr>
        <tr>
            <td>PrivateKeyPath</td>
            <td>string</td>
            <td>The path to the private key file.</td>
            <td>/app/key.pem</td>
            <td>None</td>
        </tr>
    </tbody>
</table>

#### Https inline certificate

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Certificate</td>
            <td>string</td>
            <td>The certificate as a string.</td>
            <td>Raw PEM certificate</td>
            <td>None</td>
        </tr>
        <tr>
            <td>PrivateKey</td>
            <td>string</td>
            <td>The private key as a string.</td>
            <td>Raw PEM private key</td>
            <td>None</td>
        </tr>
    </tbody>
</table>

#### Logging

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>MinimumLevel</td>
            <td>string</td>
            <td>The minimum log level, possible values are Trace, Debug, Information, Warning, Error, Critical.</td>
            <td>Information</td>
            <td>Information</td>
        </tr>
        <tr>
            <td>UseXForwardedForHeader</td>
            <td>bool</td>
            <td>Whether to use the X-Forwarded-For header, useful if behind a proxy.</td>
            <td>false</td>
            <td>false</td>
        </tr>
    </tbody>
</table>

#### Users

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Email</td>
            <td>string</td>
            <td>The email of the user.</td>
            <td>sudo@localhost</td>
            <td>None</td>
        </tr>
        <tr>
            <td>FirstName</td>
            <td>string</td>
            <td>The first name of the user.</td>
            <td>Test</td>
            <td>None</td>
        </tr>
        <tr>
            <td>LastName</td>
            <td>string</td>
            <td>The last name of the user.</td>
            <td>User</td>
            <td>None</td>
        </tr>
    </tbody>
</table>

#### Clients

<table>
    <thead>
        <tr>
            <th>Property</th>
            <th>Type</th>
            <th>Description</th>
            <th>Example</th>
            <th>Default Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Id</td>
            <td>string</td>
            <td>The ID of the client.</td>
            <td>test</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Secret</td>
            <td>string</td>
            <td>The secret of the client.</td>
            <td>ThisIsNotARealSecret</td>
            <td>None</td>
        </tr>
        <tr>
            <td>RedirectUris</td>
            <td>array</td>
            <td>The redirect URIs of the client.</td>
            <td>["http://localhost:3000/callback"]</td>
            <td>[]</td>
        </tr>
        <tr>
            <td>PostLogoutRedirectUris</td>
            <td>array</td>
            <td>The valid post logout redirect URIs of the client.</td>
            <td>["http://localhost:3000/callback"]</td>
            <td>[]</td>
        </tr>
    </tbody>
</table>

### Example JSON configuration

```json
{
    "DevOidcToolkit": {
        "Port": 8080,
        "Users": [
            {
                "Email": "sudo@localhost",
                "FirstName": "Test",
                "LastName": "User"
            }
        ],
        "Clients": [
            {
                "Id": "test",
                "Secret": "ThisIsNotARealSecret",
                "RedirectUris": [
                    "http://localhost:3000/callback"
                ]
            }
        ]
    }
}
```
