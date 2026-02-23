using System.Net;
using System.Security.Cryptography.X509Certificates;

using DevOidcToolkit.Infrastructure.Configuration;
using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.Sources.Clear();

builder.Configuration.AddJsonFile("config.json", optional: true, reloadOnChange: true);
builder.Configuration.AddEnvironmentVariables();

var configSection = builder.Configuration.GetSection(DevOidcToolkitConfiguration.Position);
var config = configSection.Get<DevOidcToolkitConfiguration>() ?? new DevOidcToolkitConfiguration();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Logging.SetMinimumLevel(LogEventLevelMapping.LogLevelType(config.Logging.MinimumLevel));

builder.Services.AddDbContext<DevOidcToolkitContext>(options =>
{
    options.UseInMemoryDatabase("dev-auth");
    options.UseOpenIddict();
});

builder.Services.AddIdentity<DevOidcToolkitUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 0;
    options.Password.RequiredUniqueChars = 0;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.User.RequireUniqueEmail = false;
})
.AddEntityFrameworkStores<DevOidcToolkitContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
});

// Add session support with secure defaults
builder.Services.AddSession(options =>
{
    options.Cookie.Name = ".DevOidcToolkit.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.IsEssential = true;
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<DevOidcToolkitContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize");
        options.SetTokenEndpointUris("connect/token");
        options.SetUserInfoEndpointUris("connect/user-info");
        options.SetEndSessionEndpointUris("connect/logout");
        options.SetIntrospectionEndpointUris("connect/introspection");

        options.AllowAuthorizationCodeFlow();
        options.AllowClientCredentialsFlow();

        options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile);
        options.RegisterClaims(Claims.Email, Claims.GivenName, Claims.FamilyName, Claims.Role);

        if (config.Issuer is not null)
        {
            options.SetIssuer(new Uri(config.Issuer));
        }

        // Register the signing and encryption credentials.
        options.AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey();

        // Register the ASP.NET Core host and configure the ASP.NET Core options.
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableStatusCodePagesIntegration()
               .EnableEndSessionEndpointPassthrough()
               .DisableTransportSecurityRequirement();
    });

builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();
builder.Services.AddRazorPages().AddRazorRuntimeCompilation();

builder.WebHost.ConfigureKestrel(options =>
{
    if (config.Address != null)
    {
        options.Listen(IPAddress.Parse(config.Address), config.Port, listenOptions =>
        {
            if (config.Https?.Inline != null)
            {
                var certPem = config.Https.Inline.Certificate;
                var keyPem = config.Https.Inline.PrivateKey;
                var x509 = X509Certificate2.CreateFromPem(certPem, keyPem);
                listenOptions.UseHttps(x509);
                return;
            }

            if (config.Https?.File != null)
            {
                var certPem = File.ReadAllText(config.Https.File.CertificatePath);
                var keyPem = File.ReadAllText(config.Https.File.PrivateKeyPath);
                var x509 = X509Certificate2.CreateFromPem(certPem, keyPem);
                listenOptions.UseHttps(x509);
                return;
            }
        });
        return;
    }

    options.ListenLocalhost(config.Port, listenOptions =>
    {
        if (config.Https?.Inline != null)
        {
            var certPem = config.Https.Inline.Certificate;
            var keyPem = config.Https.Inline.PrivateKey;
            var x509 = X509Certificate2.CreateFromPem(certPem, keyPem);
            listenOptions.UseHttps(x509);
            return;
        }

        if (config.Https?.File != null)
        {
            var certPem = File.ReadAllText(config.Https.File.CertificatePath);
            var keyPem = File.ReadAllText(config.Https.File.PrivateKeyPath);
            var x509 = X509Certificate2.CreateFromPem(certPem, keyPem);
            listenOptions.UseHttps(x509);
            return;
        }
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<DevOidcToolkitContext>();

    // Set up users and clients in the DB
    var userManager = services.GetRequiredService<UserManager<DevOidcToolkitUser>>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    for (var i = 0; i < config.Users.Count; i++)
    {
        var user = config.Users[i];
        var userEntity = new DevOidcToolkitUser()
        {
            Id = i.ToString(),
            Email = user.Email,
            UserName = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            EmailConfirmed = true,
        };
        var result = await userManager.CreateAsync(userEntity);

        if (!result.Succeeded)
        {
            throw new Exception($"Failed to set up user: ${string.Join(", ", result.Errors.Select(error => error.Description))}");
        }

        foreach (var role in user.Roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
            await userManager.AddToRoleAsync(userEntity, role);
        }
    }

    // Set up OIDC clients
    var openIddictManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    foreach (var client in config.Clients)
    {
        var clientApp = new OpenIddictApplicationDescriptor()
        {
            ClientId = client.Id,
            ClientSecret = client.Secret,
            Permissions = {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,

                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,

                Permissions.Scopes.Profile,
                Permissions.Scopes.Email
            },
            ConsentType = ConsentTypes.Explicit
        };
        client.RedirectUris.ForEach(redirectUri => clientApp.RedirectUris.Add(new Uri(redirectUri)));
        client.PostLogoutRedirectUris.ForEach(redirectUri => clientApp.PostLogoutRedirectUris.Add(new Uri(redirectUri)));
        await openIddictManager.CreateAsync(clientApp);
    }
}

app.UseDeveloperExceptionPage();
app.UseForwardedHeaders();
app.UseRouting();

app.UseSession();

app.UseCors();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

if (!app.Environment.IsDevelopment())
{

    var documentationFileProvider = new ManifestEmbeddedFileProvider(typeof(Program).Assembly, "/Documentation");
    app.Map("/documentation", documentationApp =>
    {
        documentationApp.UseDefaultFiles(new DefaultFilesOptions
        {
            FileProvider = documentationFileProvider,
            DefaultFileNames = ["index.html"],
        });

        documentationApp.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = documentationFileProvider,
        });
    });

}

app.MapControllers();
app.MapRazorPages();

app.Run();