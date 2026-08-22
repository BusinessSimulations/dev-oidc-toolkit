# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Issue access tokens as signed `RS256` JWTs instead of encrypted JWEs, so clients and resource servers can validate them against the published JWKS (see [#29](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/29))
- Add `AccessTokenFormat` config option to switch access tokens between `Jwt` and `Opaque` (see [#29](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/29))
### Breaking Changes

- **Access tokens are no longer encrypted by default**: access tokens were previously JWEs using `RSA-OAEP`, encrypted under a key that was never published, so nothing outside this application could read them. They are now signed `RS256` JWTs with a readable payload, matching Keycloak, Auth0, Okta and Cognito. Anything that relied on access tokens being opaque should set `AccessTokenFormat` to `Opaque`, which returns a random identifier instead. ID tokens are unaffected

## [0.7.0]
- Add `/healthz/live` and `/healthz/ready` healthcheck endpoint (see [#23](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/23))
- Add `HEALTHCHECK` and `curl` to Docker image (see [#23](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/23))
### Breaking Changes

- **Docker default port changed from 8080 to 80**: The `ENV DevOidcToolkit__Port=8080` environment variable has been removed from the Dockerfile. The application now listens on port 80 by default (the application's built-in default). Docker port mappings should be updated from `-p 8080:8080` to `-p 8080:80`. This fixes a bug where setting `Port` in `config.json` had no effect (see [#26](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/26))

## [0.6.0]
- Add optional SQLite persistence via `Database.SqliteFile` config option; defaults to in-memory when not set (see [#20](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/20))

## [0.5.0]
- Add configurable user roles through `DevOidcToolkit__Users__INDEX__Roles__INDEX` (see [#17](https://github.com/BusinessSimulations/dev-oidc-toolkit/pull/17))
- Add runtime user registration at `/users` page (see [#15](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/15))
- Add runtime OIDC client creation at `/clients` page (see [#15](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/15))

## [0.4.0]
- Add configurable `Issuer` field to override the `iss` claim in tokens and the OIDC discovery document (see [#13](https://github.com/BusinessSimulations/dev-oidc-toolkit/issues/13))

## [0.3.0]
- Add support for `post_logout_redirect_uris`, (see [#10](https://github.com/BusinessSimulations/dev-oidc-toolkit/pull/10))
- Update to dotnet 10

## [0.2.0]
- Add `email_verified` claim for compatibility with [pocketbase](https://github.com/pocketbase/pocketbase), (see
[#6](https://github.com/BusinessSimulations/dev-oidc-toolkit/pull/6))

## [0.1.0] - 2025-06-23
- Initial release

[Unreleased]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.7.0...HEAD
[0.7.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.6.0...0.7.0
[0.6.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.5.0...0.6.0
[0.5.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.4.0...0.5.0
[0.4.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.3.0...0.4.0
[0.3.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.2.0...0.3.0
[0.2.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.1.0...0.2.0
[0.1.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/releases/tag/0.1.0
