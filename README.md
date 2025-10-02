# dev-oidc-toolkit

A simple OpenID Connect identity provider for development and testing.

[![Business Simulations Logo](https://businesssimulations.com/logo.png)](https://businesssimulations.com/)

[Maintained by Business Simulations](https://businesssimulations.com/).

## What is it?

This project is a simple OpenID Connect identity provider. It provides a minimal, easy to configure, and lightweight
identity server for use in local development and automated testing environments. The tool can be easily ran through
docker or with a self-contained binary, and can be configured with environment variables or configuration files.

The project is **NOT for production use**. The users that are configured are configured without any passwords, so
you can log in as any user by just selecting them from a list. This is obviously not something you want in a real
environment, but it is useful for development and testing as you do not need to remember passwords.

## Why would I use it?

This is useful for local development when you need to integrate an application with OpenID Connect. This tool lets
you check that your application's integration is working correctly, and helps provide some useful debug information
that other tools might hide for security reasons (see the logging provided).

The tool is easy to configure with static users and clients, and can be spun up and down very quickly. It is portable
and dockerized, making it perfect for use with end-to-end testing, saving you from having to spin up a real
identity provider such as Keycloak as part of your testing pipeline.

## Features

- Simple OpenID Connect identity provider
- Support for client credentials grant type
- Support for authorization code grant type
- Create users through configuration
- Create OpenID Connect clients through configuration
- List configured users
- List configured clients
- Different levels of logging to help with debugging
- Built in documentation
- Distributed as a self-contained binaries
- Distributed as Docker images

## Documentation

Access the documentatation here: <https://dev-oidc-toolkit.readthedocs.io/en/latest/>.

## Getting started

The easiest way to run this application is using docker, use this command:

```bash
docker run -p 8080:8080                                                               \
    -e DevOidcToolkit__Users__0__Email=test@localhost                                 \
    -e DevOidcToolkit__Users__0__FirstName=Test                                       \
    -e DevOidcToolkit__Users__0__LastName=User                                        \
    -e DevOidcToolkit__Users__1__Email=test2@localhost                                \
    -e DevOidcToolkit__Users__1__FirstName=Test2                                      \
    -e DevOidcToolkit__Users__1__LastName=User2                                       \
    -e DevOidcToolkit__Clients__0__Id=client                                          \
    -e DevOidcToolkit__Clients__0__Secret=secret                                      \
    -e DevOidcToolkit__Clients__0__RedirectUris__INDEX=http://localhost:3000/callback \
    ghcr.io/businesssimulations/dev-oidc-toolkit
```

This will run the application and make it available at `http://localhost:8080`, with the following configured:

- A user with the email `test@localhost` and the name `Test User`
- A user with the email `test2@localhost` and the name `Test2 User2`
- A client with the ID `client` and the secret `secret`, with a redirect URI of `http://localhost:3000/callback`

This uses environment variables to configure the application, but the application can also be configured using a JSON
configuration file. See the [documentation](https://dev-oidc-toolkit.readthedocs.io/en/latest/configuration) for
more information.

There are also pre-built binaries available for download from the
[releases page](https://github.com/BusinessSimulations/dev-oidc-toolkit/releases).

### Potential future features

- [Custom scope and claim mapping](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/1)
- [Wildcard redirect URIs](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/2)

## License

This project is [licensed under the MIT license](./LICENSE.md), meaning it is free for personal and commercial use.

## Contributing

If you are interested in contributing in any way to this project (bug reports, feature suggestions, code changes)
please read the [contributing guidelines](./CONTRIBUTING.md) first.
