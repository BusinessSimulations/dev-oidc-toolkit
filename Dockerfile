# Docs build
FROM python:3.14 AS docs-build
WORKDIR /docs

COPY DevOidcToolkit.Documentation /docs

RUN pip install -r requirements.txt
RUN mkdocs build



# App build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /app

ARG VERSION=0.0.0.0

# Copy csproj and restore as distinct layers
COPY DevOidcToolkit/DevOidcToolkit.csproj ./

RUN dotnet restore

# Copy everything else
COPY DevOidcToolkit/ ./
COPY --from=docs-build /docs/build ./Documentation/

# Build and publish a release
RUN dotnet publish -c Release --no-restore /p:SelfContained=false /p:PublishSingleFile=false -o dist



# App runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/dist .

ENTRYPOINT ["dotnet", "dev-oidc-toolkit.dll"]

ENV DevOidcToolkit__Port=8080
ENV DevOidcToolkit__Address=0.0.0.0
EXPOSE 8080
