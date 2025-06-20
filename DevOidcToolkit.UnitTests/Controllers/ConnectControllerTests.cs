namespace DevOidcToolkit.UnitTests.Controllers;

using System.Security.Claims;
using System.Threading.Tasks;

using DevOidcToolkit.Controllers;
using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

using Xunit;

using static OpenIddict.Abstractions.OpenIddictConstants;


public static class MockSignInManager
{
    public static Mock<SignInManager<TUser>> CreateMockSignInManager<TUser>(
        UserManager<TUser>? userManager = null,
        IHttpContextAccessor? contextAccessor = null,
        IUserClaimsPrincipalFactory<TUser>? claimsFactory = null,
        IOptions<IdentityOptions>? optionsAccessor = null,
        ILogger<SignInManager<TUser>>? logger = null,
        IAuthenticationSchemeProvider? schemes = null,
        IUserConfirmation<TUser>? confirmation = null) where TUser : class
    {
        userManager ??= MockUserManager.CreateMockUserManager<TUser>().Object;
        contextAccessor ??= new Mock<IHttpContextAccessor>().Object;
        claimsFactory ??= new Mock<IUserClaimsPrincipalFactory<TUser>>().Object;
        optionsAccessor ??= new OptionsManager<IdentityOptions>(
            new OptionsFactory<IdentityOptions>([], []));
        logger ??= new Mock<ILogger<SignInManager<TUser>>>().Object;
        schemes ??= new Mock<IAuthenticationSchemeProvider>().Object;
        confirmation ??= new Mock<IUserConfirmation<TUser>>().Object;

        var mock = new Mock<SignInManager<TUser>>(
            userManager,
            contextAccessor,
            claimsFactory,
            optionsAccessor,
            logger,
            schemes,
            confirmation);

        return mock;
    }
}

public static class MockUserManager
{
    public static Mock<UserManager<TUser>> CreateMockUserManager<TUser>(
        IUserStore<TUser>? store = null,
        IOptions<IdentityOptions>? options = null,
        IPasswordHasher<TUser>? passwordHasher = null,
        IEnumerable<IUserValidator<TUser>>? userValidators = null,
        IEnumerable<IPasswordValidator<TUser>>? passwordValidators = null,
        ILookupNormalizer? keyNormalizer = null,
        IdentityErrorDescriber? errors = null,
        IServiceProvider? services = null,
        ILogger<UserManager<TUser>>? logger = null) where TUser : class
    {
        store ??= new Mock<IUserStore<TUser>>().Object;
        options ??= new OptionsManager<IdentityOptions>(new OptionsFactory<IdentityOptions>(
            [],
            []));
        passwordHasher ??= new Mock<IPasswordHasher<TUser>>().Object;
        userValidators ??= [];
        passwordValidators ??= [];
        keyNormalizer ??= new UpperInvariantLookupNormalizer();
        errors ??= new IdentityErrorDescriber();
        services ??= new ServiceCollection().BuildServiceProvider();
        logger ??= new Mock<ILogger<UserManager<TUser>>>().Object;

        var mock = new Mock<UserManager<TUser>>(
            store,
            options,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services,
            logger);

        return mock;
    }
}


public class ConnectControllerAuthorizeTests
{
    private static ConnectController CreateController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<DevOidcToolkitUser> userManager,
        SignInManager<DevOidcToolkitUser> signInManager,
        ILogger<ConnectController>? logger = null,
        bool isAuthenticated = false,
        string? userId = null,
        string? userName = null)
    {
        logger ??= new Mock<ILogger<ConnectController>>().Object;

        var controller = new ConnectController(
            logger,
            applicationManager,
            userManager,
            signInManager);

        if (isAuthenticated)
        {
            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, userId ?? Guid.NewGuid().ToString()),
                        new Claim(ClaimTypes.Name, userName ?? "testuser")
                    ],
                    IdentityConstants.ApplicationScheme));

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = user }
            };
        }

        else
        {
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
        }


        return controller;
    }


    [Fact]
    public async void Authorize_WhenUserNotAuthenticated_ReturnsChallengeResult()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: false);

        // Act
        var result = await controller.Authorize();

        // Assert
        Assert.IsType<ChallengeResult>(result);
    }

    [Fact]
    public async Task Authorize_WhenClientIdDoesNotExist_ReturnsForbidResult()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager to return null (client not found)
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.Authorize();

        // Assert
        var forbidResult = Assert.IsType<ForbidResult>(result);
        Assert.Equal(1, forbidResult.AuthenticationSchemes?.Count);
        Assert.Equal(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, forbidResult.AuthenticationSchemes?[0]);

        // Verify the error properties
        var properties = forbidResult.Properties;
        Assert.NotNull(properties);
        Assert.True(properties.Items.TryGetValue(OpenIddictServerAspNetCoreConstants.Properties.Error, out var error));
        Assert.Equal(Errors.InvalidClient, error);
        Assert.True(properties.Items.TryGetValue(OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription, out var errorDescription));
        Assert.Equal("The client application cannot be found.", errorDescription);
    }


    [Fact]
    public async Task Authorize_WhenUserAuthenticatedWithValidRequest_ReturnsSignInResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Set up OIDC app manager
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(testApp);

        // Setup test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        // Setup user manager
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                  .ReturnsAsync(testUser);


        // Setup sign in manager
        var claimsIdentity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(claimsIdentity);
        signInManager.Setup(x => x.CreateUserPrincipalAsync(testUser))
                    .ReturnsAsync(principal);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: testUser.Id,
            userName: testUser.UserName);

        // Setup form content to simulate consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Setup consent type to not require explicit consent for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Act
        var result = await controller.Authorize();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }


    [Fact]
    public async Task Authorize_WhenOpenIdRequestMissing_ThrowsInvalidOperationException()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: "123",
            userName: "testuser");

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.Authorize());

        Assert.Equal("The OpenID Connect request cannot be retrieved.", exception.Message);
    }

    [Fact]
    public async Task Authorize_WhenUserNotFound_ThrowsInvalidOperationException()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager to return a test app
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(testApp);

        // Setup consent type to not require explicit consent for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Setup user manager to return null user
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                  .ReturnsAsync((DevOidcToolkitUser?)null);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: "123",
            userName: "testuser");

        // Set form content to simulate consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.Authorize());

        Assert.Equal("The user details cannot be retrieved.", exception.Message);
    }

    [Fact]
    public async Task Authorize_WhenConsentRequired_ShowsConsentView()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager to require explicit consent
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Explicit);
        oidcAppManager.Setup(x => x.GetDisplayNameAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");
        oidcAppManager.Setup(x => x.GetClientIdAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("test-client");

        // Setup test user
        var testUser = new DevOidcToolkitUser() { Id = "user123", UserName = "testuser", FirstName = "Test", LastName = "User" };
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                .ReturnsAsync(testUser);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup OpenIddict request with scopes
        var request = new OpenIddictRequest
        {
            ClientId = "test-client",
            Scope = "openid profile email"
        };
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.Authorize();

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Consent", viewResult.ViewName);
        Assert.Equal("test-client", viewResult.ViewData["ClientName"]);
        Assert.Equal(new List<string> { "openid", "profile", "email" }, viewResult.ViewData["Scopes"]);
    }

    [Fact]
    public async Task Authorize_WhenConsentNotRequired_ReturnsSignInResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager with implicit consent
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);
        oidcAppManager.Setup(x => x.GetDisplayNameAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");
        oidcAppManager.Setup(x => x.GetClientIdAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("test-client");

        // Setup test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                .ReturnsAsync(testUser);

        // Setup sign in manager
        var claimsIdentity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(claimsIdentity);
        signInManager.Setup(x => x.CreateUserPrincipalAsync(testUser))
                    .ReturnsAsync(principal);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup OpenIddict request with scopes
        var request = new OpenIddictRequest
        {
            Scope = "openid profile email"
        };
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Setup consent type to implicit for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Setup form content for the request
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Act
        var result = await controller.Authorize();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }
}


public class ConnectControllerAuthorizePostTests
{
    private static ConnectController CreateController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<DevOidcToolkitUser> userManager,
        SignInManager<DevOidcToolkitUser> signInManager,
        ILogger<ConnectController>? logger = null,
        bool isAuthenticated = false,
        string? userId = null,
        string? userName = null)
    {
        logger ??= new Mock<ILogger<ConnectController>>().Object;

        var controller = new ConnectController(
            logger,
            applicationManager,
            userManager,
            signInManager);

        if (isAuthenticated)
        {
            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, userId ?? Guid.NewGuid().ToString()),
                        new Claim(ClaimTypes.Name, userName ?? "testuser")
                    ],
                    IdentityConstants.ApplicationScheme));

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = user }
            };
        }

        else
        {
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
        }


        return controller;
    }


    [Fact]
    public async void AuthorizePost_WhenUserNotAuthenticated_ReturnsChallengeResult()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: false);

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        Assert.IsType<ChallengeResult>(result);
    }


    [Fact]
    public async Task AuthorizePost_WhenUserAuthenticatedWithValidRequest_ReturnsSignInResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Set up OIDC app manager
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(testApp);

        // Setup test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        // Setup user manager
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                  .ReturnsAsync(testUser);


        // Setup sign in manager
        var claimsIdentity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(claimsIdentity);
        signInManager.Setup(x => x.CreateUserPrincipalAsync(testUser))
                    .ReturnsAsync(principal);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: testUser.Id,
            userName: testUser.UserName);

        // Setup form content to simulate consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Setup consent type to not require explicit consent for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }


    [Fact]
    public async Task AuthorizePost_WhenOpenIdRequestMissing_ThrowsInvalidOperationException()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: "123",
            userName: "testuser");

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.AuthorizePost());

        Assert.Equal("The OpenID Connect request cannot be retrieved.", exception.Message);
    }

    [Fact]
    public async Task AuthorizePost_WhenUserNotFound_ThrowsInvalidOperationException()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager to return a test app
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(testApp);

        // Setup consent type to not require explicit consent for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Setup user manager to return null user
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                  .ReturnsAsync((DevOidcToolkitUser?)null);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true,
            userId: "123",
            userName: "testuser");

        // Set form content to simulate consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.AuthorizePost());

        Assert.Equal("The user details cannot be retrieved.", exception.Message);
    }

    [Fact]
    public async Task AuthorizePost_WhenClientIdDoesNotExist_ReturnsForbidResult()
    {
        // Arrange
        object? testApp = null;
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup form collection with denied consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "no"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        var forbidResult = Assert.IsType<ForbidResult>(result);
        Assert.Contains(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, forbidResult.AuthenticationSchemes);
    }

    [Fact]
    public async Task AuthorizePost_WhenConsentDenied_ReturnsForbidResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup form collection with denied consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "no"
        });

        // Setup OpenIddict request
        var request = new OpenIddictRequest();
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        var forbidResult = Assert.IsType<ForbidResult>(result);
        Assert.Contains(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, forbidResult.AuthenticationSchemes);
    }

    [Fact]
    public async Task AuthorizePost_WhenConsentGranted_ReturnsSignInResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);

        // Setup test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                .ReturnsAsync(testUser);

        // Setup sign in manager
        var claimsIdentity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(claimsIdentity);
        signInManager.Setup(x => x.CreateUserPrincipalAsync(testUser))
                    .ReturnsAsync(principal);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup form collection with granted consent
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Setup OpenIddict request with scopes
        var request = new OpenIddictRequest
        {
            Scope = "openid profile email"
        };
        var feature = new OpenIddictServerAspNetCoreFeature() { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }

    [Fact]
    public async Task AuthorizePost_WhenConsentNotRequired_ReturnsSignInResult()
    {
        // Arrange
        var testApp = new object();
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Setup OIDC app manager with implicit consent
        oidcAppManager.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(testApp);
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);
        oidcAppManager.Setup(x => x.GetDisplayNameAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");
        oidcAppManager.Setup(x => x.GetClientIdAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("test-client");

        // Setup test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                .ReturnsAsync(testUser);

        // Setup sign in manager
        var claimsIdentity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(claimsIdentity);
        signInManager.Setup(x => x.CreateUserPrincipalAsync(testUser))
                    .ReturnsAsync(principal);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            isAuthenticated: true);

        // Setup OpenIddict request with scopes
        var request = new OpenIddictRequest
        {
            Scope = "openid profile email"
        };
        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Setup consent type to implicit for this test
        oidcAppManager.Setup(x => x.GetConsentTypeAsync(testApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Implicit);

        // Setup form content for the request
        controller.ControllerContext.HttpContext.Request.Method = "POST";
        controller.ControllerContext.HttpContext.Request.ContentType = "application/x-www-form-urlencoded";
        controller.ControllerContext.HttpContext.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["consent"] = "yes"
        });

        // Act
        var result = await controller.AuthorizePost();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }
}

public class ConnectControllerExchangeTests
{
    private static ConnectController CreateController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<DevOidcToolkitUser> userManager,
        SignInManager<DevOidcToolkitUser> signInManager,
        ILogger<ConnectController>? logger = null)
    {
        logger ??= new Mock<ILogger<ConnectController>>().Object;

        var controller = new ConnectController(
            logger,
            applicationManager,
            userManager,
            signInManager)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        return controller;
    }

    [Fact]
    public async Task Exchange_WithClientCredentialsGrant_ReturnsSignInResult()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var testApp = Mock.Of<object>();
        oidcAppManager.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(testApp);
        oidcAppManager.Setup(x => x.GetClientIdAsync(testApp, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("test-client");
        oidcAppManager.Setup(x => x.GetDisplayNameAsync(testApp, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("Test Application");
        oidcAppManager.Setup(x => x.ValidateClientSecretAsync(testApp, It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(true);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        var request = new OpenIddictRequest
        {
            GrantType = GrantTypes.ClientCredentials,
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };

        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.Exchange();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
        oidcAppManager.Verify(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Exchange_WithClientCredentialsGrant_InvalidClient_ThrowsException()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        oidcAppManager.Setup(x => x.FindByClientIdAsync("invalid-client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((object?)null);

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        var request = new OpenIddictRequest
        {
            GrantType = GrantTypes.ClientCredentials,
            ClientId = "invalid-client"
        };

        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.Exchange());

        Assert.Equal("The client application cannot be found.", exception.Message);
    }

    [Fact]
    public async Task Exchange_WithAuthorizationCodeGrant_ReturnsSignInResult()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        // Create a test user
        var testUser = new DevOidcToolkitUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User"
        };

        // Setup user manager
        userManager.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
                 .ReturnsAsync(testUser);


        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        // Setup OpenIddict request
        var request = new OpenIddictRequest
        {
            GrantType = GrantTypes.AuthorizationCode,
            Code = "test-code"
        };

        // Setup authentication context
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.AddClaim(Claims.Subject, testUser.Id);
        identity.AddClaim(Claims.Name, testUser.UserName);
        identity.AddClaim(Claims.Email, testUser.Email);

        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Mock authentication
        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock
            .Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
            .ReturnsAsync(AuthenticateResult.Success(ticket));


        var serviceProvider = new ServiceCollection()
            .AddSingleton(authServiceMock.Object)
            .BuildServiceProvider();

        controller.ControllerContext.HttpContext.RequestServices = serviceProvider;

        // Setup OpenIddict feature
        var feature = new OpenIddictServerAspNetCoreFeature
        {
            Transaction = new()
            {
                Request = request,
                EndpointType = OpenIddictServerEndpointType.Token
            }
        };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.Exchange();

        // Assert
        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
        authServiceMock.Verify(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task Exchange_WithUnsupportedGrantType_ReturnsBadRequest()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        var request = new OpenIddictRequest
        {
            GrantType = "unsupported_grant_type"
        };

        var feature = new OpenIddictServerAspNetCoreFeature { Transaction = new() { Request = request } };
        controller.HttpContext.Features.Set(feature);

        // Act
        var result = await controller.Exchange();
        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        var errorResponse = Assert.IsType<OpenIddictResponse>(badRequestResult.Value);
        Assert.Equal(Errors.UnsupportedGrantType, errorResponse.Error);
        Assert.Equal("The specified grant type is not supported.", errorResponse.ErrorDescription);
    }
}


public class ConnectControllerLogoutTests
{
    private static ConnectController CreateController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<DevOidcToolkitUser> userManager,
        SignInManager<DevOidcToolkitUser> signInManager,
        ILogger<ConnectController>? logger = null)
    {
        logger ??= new Mock<ILogger<ConnectController>>().Object;

        var controller = new ConnectController(
            logger,
            applicationManager,
            userManager,
            signInManager)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        return controller;
    }

    [Fact]
    public async Task Logout_WhenCalled_SignsOutBothSchemesAndRedirectsToRoot()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock
            .Setup(x => x.SignOutAsync(
                It.IsAny<HttpContext>(),
                IdentityConstants.ApplicationScheme,
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        authServiceMock
            .Setup(x => x.SignOutAsync(
                It.IsAny<HttpContext>(),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        var serviceProvider = new ServiceCollection()
            .AddSingleton(authServiceMock.Object)
            .BuildServiceProvider();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        controller.ControllerContext.HttpContext.RequestServices = serviceProvider;

        // Act
        var result = await controller.Logout();

        // Assert
        var signOutResult = Assert.IsType<SignOutResult>(result);
        Assert.Single(signOutResult.AuthenticationSchemes);
        Assert.Contains(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, signOutResult.AuthenticationSchemes);

        authServiceMock.Verify(x => x.SignOutAsync(
            It.IsAny<HttpContext>(),
            IdentityConstants.ApplicationScheme,
            It.IsAny<AuthenticationProperties>()), Times.Once);

        authServiceMock.Verify(x => x.SignOutAsync(
            It.IsAny<HttpContext>(),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task Logout_WhenSignOutFails_ThrowsException()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock
            .Setup(x => x.SignOutAsync(
                It.IsAny<HttpContext>(),
                IdentityConstants.ApplicationScheme,
                It.IsAny<AuthenticationProperties>()))
            .ThrowsAsync(new Exception("Sign out failed"));

        var serviceProvider = new ServiceCollection()
            .AddSingleton(authServiceMock.Object)
            .BuildServiceProvider();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        controller.ControllerContext.HttpContext.RequestServices = serviceProvider;

        // Act & Assert
        await Assert.ThrowsAsync<Exception>(() => controller.Logout());

        authServiceMock.Verify(x => x.SignOutAsync(
            It.IsAny<HttpContext>(),
            IdentityConstants.ApplicationScheme,
            It.IsAny<AuthenticationProperties>()), Times.Once);
    }
}

public class ConnectControllerUserInfoTests
{
    private static ConnectController CreateController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<DevOidcToolkitUser> userManager,
        SignInManager<DevOidcToolkitUser> signInManager,
        ILogger<ConnectController>? logger = null,
        ClaimsPrincipal? user = null)
    {
        logger ??= new Mock<ILogger<ConnectController>>().Object;

        var controller = new ConnectController(
            logger,
            applicationManager,
            userManager,
            signInManager)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = user ?? new ClaimsPrincipal()
                }
            }
        };

        return controller;
    }

    private static ClaimsPrincipal CreateUserPrincipal(string? scope = null, string? sub = "123", string? email = null, string? name = null, string? givenName = null, string? familyName = null)
    {
        var claims = new List<Claim>();

        if (sub != null)
            claims.Add(new(Claims.Subject, sub));

        if (scope != null)
            claims.Add(new("scope", scope));

        if (email != null)
            claims.Add(new(Claims.Email, email));

        if (name != null)
            claims.Add(new(Claims.Name, name));

        if (givenName != null)
            claims.Add(new(Claims.GivenName, givenName));

        if (familyName != null)
            claims.Add(new(Claims.FamilyName, familyName));

        return new ClaimsPrincipal(
            new ClaimsIdentity(claims, "TestAuthType"));
    }

    [Fact]
    public void UserInfo_WhenNotAuthenticated_ReturnsUnauthorized()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object);

        // Act
        var result = controller.UserInfo();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }


    [Fact]
    public void UserInfo_WhenMissingSubClaim_ReturnsBadRequest()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal(sub: null);
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var response = new JsonResult(badRequest.Value).Value as dynamic;
        Assert.NotNull(response);
        string? error = response?.GetType().GetProperty("error")?.GetValue(response) as string;
        Assert.Equal("Missing sub claim", error);
    }

    [Fact]
    public void UserInfo_WithEmailScope_IncludesEmailInResponse()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("email", email: "test@example.com");
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Equal("test@example.com", claims["email"]);
    }

    [Fact]
    public void UserInfo_WithoutEmailScope_ExcludesEmailFromResponse()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("profile", email: "test@example.com");
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.False(claims.ContainsKey("email"));
    }

    [Fact]
    public void UserInfo_WithProfileScope_IncludesProfileClaims()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("profile", name: "Test User", givenName: "Test", familyName: "User");
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Equal("Test User", claims["name"]);
        Assert.Equal("Test", claims["given_name"]);
        Assert.Equal("User", claims["family_name"]);
    }

    [Fact]
    public void UserInfo_WithoutProfileScope_ExcludesProfileClaims()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("email", name: "Test User", givenName: "Test", familyName: "User");
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.False(claims.ContainsKey("name"));
        Assert.False(claims.ContainsKey("given_name"));
        Assert.False(claims.ContainsKey("family_name"));
    }

    [Fact]
    public void UserInfo_WithAllScopes_ReturnsCompleteUserInfo()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("email profile",
            email: "test@example.com",
            name: "Test User",
            givenName: "Test",
            familyName: "User");

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Equal("123", claims["sub"]);
        Assert.Equal("test@example.com", claims["email"]);
        Assert.Equal("Test User", claims["name"]);
        Assert.Equal("Test", claims["given_name"]);
        Assert.Equal("User", claims["family_name"]);
    }

    [Fact]
    public void UserInfo_WithNoScopes_ReturnsOnlySub()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("",
            email: "test@example.com",
            name: "Test User",
            givenName: "Test",
            familyName: "User");

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Single(claims);
        Assert.Equal("123", claims["sub"]);
    }

    [Fact]
    public void UserInfo_WithInvalidScope_IgnoresUnknownScopes()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("invalid_scope another_invalid_scope",
            email: "test@example.com");

        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Single(claims); // Only 'sub' should be present
        Assert.Equal("123", claims["sub"]);
    }


    [Fact]
    public void UserInfo_WithNullValues_HandlesGracefully()
    {
        // Arrange
        var oidcAppManager = new Mock<IOpenIddictApplicationManager>();
        var userManager = MockUserManager.CreateMockUserManager<DevOidcToolkitUser>();
        var signInManager = MockSignInManager.CreateMockSignInManager<DevOidcToolkitUser>();

        var user = CreateUserPrincipal("email profile");
        var controller = CreateController(
            oidcAppManager.Object,
            userManager.Object,
            signInManager.Object,
            user: user);

        // Act
        var result = controller.UserInfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claims = Assert.IsType<Dictionary<string, string>>(okResult.Value);
        Assert.Single(claims); // Only 'sub' should be present
        Assert.Equal("123", claims["sub"]);
    }
}