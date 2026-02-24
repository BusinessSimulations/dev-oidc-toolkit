# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Add configurable user roles through `DevOidcToolkit__Users__INDEX__Roles__INDEX`
- Add runtime user registration at `/users` page
- Add runtime OIDC client creation at `/clients` page

## [0.4.0]
- Add configurable `Issuer` field to override the `iss` claim in tokens and the OIDC discovery document

## [0.3.0]
- Add support for `post_logout_redirect_uris`, see [#10](https://github.com/BusinessSimulations/dev-oidc-toolkit/pull/10)
- Update to dotnet 10

## [0.2.0]
- Add `email_verified` claim for compatibility with [pocketbase](https://github.com/pocketbase/pocketbase), see
[#6](https://github.com/BusinessSimulations/dev-oidc-toolkit/pull/6)

## [0.1.0] - 2025-06-23
- Initial release

[Unreleased]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.4.0...HEAD
[0.4.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.3.0...0.4.0
[0.3.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.2.0...0.3.0
[0.2.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/compare/0.1.0...0.2.0
[0.1.0]:
https://github.com/BusinessSimulations/dev-oidc-toolkit/releases/tag/0.1.0
