# Tutorial

In this tutorial we will go through the process of setting up a simple OpenID Connect identity provider using
[dev-oidc-toolkit](https://github.com/BusinessSimulations/dev-oidc-toolkit) and test it by configuring an OAuth2-proxy
instance to use it as an identity provider.

## Prerequisites

- [Docker](https://www.docker.com/) - to run the dev-oidc-toolkit
- [Go](https://golang.org/) - to run the OAuth2-proxy

## Steps

1. Spin up the dev-oidc-toolkit container:

```bash
docker run --rm -p 8080:8080                                                                 \
    --name dev-oidc-toolkit                                                                  \
    -e DevOidcToolkit__Users__0__Email=test@localhost                                        \
    -e DevOidcToolkit__Users__0__FirstName=Test                                              \
    -e DevOidcToolkit__Users__0__LastName=User                                               \
    -e DevOidcToolkit__Clients__0__Id=client                                                 \
    -e DevOidcToolkit__Clients__0__Secret=secret                                             \
    -e DevOidcToolkit__Clients__0__RedirectUris__INDEX=http://localhost:4180/oauth2/callback \
    ghcr.io/businesssimulations/dev-oidc-toolkit
```

This will run the application and make it available at `http://localhost:8080`, with the following configured:

- A user with the email `test@localhost` and the name `Test User`
- A client with the ID `client` and the secret `secret`, with a redirect URI of `http://localhost:4180/oauth2/callback`

2. Start the OAuth2-proxy:

```bash
go run github.com/oauth2-proxy/oauth2-proxy/v7@latest    \
    --provider=oidc                                      \
    --client-id=client                                   \
    --client-secret=secret                               \
    --oidc-issuer-url=http://localhost:8080/             \
    --redirect-url=http://localhost:4180/oauth2/callback \
    --email-domain='*'                                   \
    --upstream=http://httpbin.org                        \
    --cookie-secret=$(openssl rand -base64 16)           \
    --cookie-secure=false
```

This will run the OAuth2-proxy and make it available at `http://localhost:4180`, with the following configured:

- A client with the ID `client` and the secret `secret`, with a redirect URI of `http://localhost:4180/oauth2/callback`

3. Load up the OAuth2-proxy in your browser at <http://localhost:4180> and you should be able to log in through the
dev-oidc-toolkit with the user `test@localhost` and the password `test`.
