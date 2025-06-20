# Architecture

This project is pretty straight-forward, it is designed to be as minimal and lightweight as possible.

The tool is an ASP Dotnet + C Sharp application.

The user interface is rendered using Razor pages.

The OpenID Connect implementation is mostly using [the OpenIddict project](https://openiddict.com/).

The documentation uses [MkDocs](https://www.mkdocs.org/) and [Material for
MkDocs](https://squidfunk.github.io/mkdocs-material/). This documentation is both provided on readthedocs and built
in to the application itself.

The application reads the configuration on start up and then populates an in-memory database with users and OpenID
connect clients. This means there is no persistence between application restarts, as the in-memory database is
wiped and a new one is used.

The frontend is styled using basic styling, using the [Sakura CSS library](https://github.com/oxalorg/sakura).

The application is dockerised and can be run as a self-contained binary or in a docker container.
