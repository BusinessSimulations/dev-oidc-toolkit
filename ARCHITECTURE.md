# Architecture

This project is pretty straight-forward, it is designed to be as minimal and lightweight as possible.

The tool is an ASP Dotnet + C Sharp application.

The user interface is rendered using Razor pages.

The OpenID Connect implementation is mostly using [the OpenIddict project](https://openiddict.com/).

The documentation uses [MkDocs](https://www.mkdocs.org/) and [Material for
MkDocs](https://squidfunk.github.io/mkdocs-material/). This documentation is both provided on readthedocs and built
in to the application itself.

The application reads the configuration on start up and then populates the database with users and OpenID connect
clients. By default, an in-memory database is used and all data is lost on restart — any users or clients created at
runtime through the web interface will not survive a restart. Optionally, a SQLite database file can be configured to
persist data between restarts; see the [Database configuration](DevOidcToolkit.Documentation/docs/configuration.md)
for details.

The frontend is styled using basic styling, using the [Sakura CSS library](https://github.com/oxalorg/sakura).

The application is dockerised and can be run as a self-contained binary or in a docker container.
