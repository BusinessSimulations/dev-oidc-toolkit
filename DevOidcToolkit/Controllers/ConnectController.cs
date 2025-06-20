using System.Security.Claims;

using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace DevOidcToolkit.Controllers;

public class ConnectController(ILogger<ConnectController> logger,
                               IOpenIddictApplicationManager applicationManager,
                               UserManager<DevOidcToolkitUser> userManager,
                               SignInManager<DevOidcToolkitUser> signInManager) : Controller
{
    private readonly ILogger<ConnectController> _logger = logger;
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly UserManager<DevOidcToolkitUser> _userManager = userManager;
    private readonly SignInManager<DevOidcToolkitUser> _signInManager = signInManager;

    [HttpGet("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            _logger.LogInformation("User is not authenticated. Redirecting to login.");
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.Path + Request.QueryString
                });
        }

        _logger.LogDebug("User {UserName} is authenticated. Processing authorization request.", User.Identity.Name);

        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        _logger.LogDebug("Authorization request details: {Request}", new
        {
            request.ClientId,
            request.ResponseType,
            request.Scope,
            request.RedirectUri
        });

        var app = await _applicationManager.FindByClientIdAsync(request.ClientId!);
        if (app == null)
        {
            _logger.LogError("Client application with ID {ClientId} not found.", request.ClientId);
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client application cannot be found."
                }));
        }

        _logger.LogDebug("Found client application: {ClientId}", request.ClientId);

        var consentType = await _applicationManager.GetConsentTypeAsync(app);
        var promptValues = request.GetPromptValues();
        var needsConsent = consentType == ConsentTypes.Explicit || promptValues.Contains("consent");

        if (needsConsent)
        {
            _logger.LogInformation("User {UserName} needs consent for client {ClientId}", User.Identity.Name, request.ClientId);
            ViewBag.ClientName = request.ClientId;
            ViewBag.Scopes = request.GetScopes().ToList();

            return View("Consent");
        }

        return await ProcessAuthorizationRequest(request);
    }

    [HttpPost("~/connect/authorize")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AuthorizePost()
    {
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            _logger.LogInformation("User is not authenticated. Redirecting to login.");
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.Path + Request.QueryString
                });
        }

        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        _logger.LogDebug("Authorization request details: {Request}", new
        {
            request.ClientId,
            request.ResponseType,
            request.Scope,
            request.RedirectUri
        });

        var consent = Request.Form["consent"];
        if (consent != "yes")
        {
            _logger.LogInformation("User {UserName} denied consent for client {ClientId}", User.Identity.Name, request.ClientId);
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user denied the consent request."
                }));
        }

        return await ProcessAuthorizationRequest(request);
    }

    private async Task<IActionResult> ProcessAuthorizationRequest(OpenIddictRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            _logger.LogError("User details cannot be retrieved.");
            throw new InvalidOperationException("The user details cannot be retrieved.");
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        principal.SetClaim(Claims.Subject, user.Id);
        principal.SetClaim(Claims.Name, user.UserName);
        principal.SetClaim(Claims.Email, user.Email);
        principal.SetClaim(Claims.GivenName, user.FirstName);
        principal.SetClaim(Claims.FamilyName, user.LastName);

        principal.SetScopes(request.GetScopes());
        principal.SetResources("resource_server");

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(
                claim.Type switch
                {
                    Claims.Name => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                    Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.Email => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.GivenName => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.FamilyName => [Destinations.AccessToken, Destinations.IdentityToken],
                    _ => [Destinations.AccessToken],
                });
        }

        _logger.LogInformation("User {UserName} authorized for client {ClientId}", user.UserName, request.ClientId);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                  ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            var app = await _applicationManager.FindByClientIdAsync(request.ClientId!)
                ?? throw new InvalidOperationException("The client application cannot be found.");

            if (request.ClientSecret == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client secret is invalid."
                    }));
            }

            if (!await _applicationManager.ValidateClientSecretAsync(app, request.ClientSecret))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client secret is invalid."
                    }));
            }

            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

            identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(app));
            identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(app));

            identity.SetDestinations(static claim => claim.Type switch
            {
                Claims.Name => [Destinations.AccessToken],
                Claims.Subject => [Destinations.AccessToken],
                _ => [Destinations.AccessToken]
            });

            var principal = new ClaimsPrincipal(identity);
            var requestedScopes = request.GetScopes().Any() ? request.GetScopes() : principal.GetScopes();
            principal.SetScopes(requestedScopes);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal ?? throw new InvalidOperationException("The authentication result does not contain a principal.");

            var requestedScopes = request.GetScopes().Any() ? request.GetScopes() : principal.GetScopes();
            principal.SetScopes(requestedScopes);

            foreach (var claim in principal.Claims)
            {
                _ = claim.SetDestinations(claim.Type switch
                {
                    Claims.Name => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                    Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.Email => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.GivenName => [Destinations.AccessToken, Destinations.IdentityToken],
                    Claims.FamilyName => [Destinations.AccessToken, Destinations.IdentityToken],
                    _ => [Destinations.AccessToken]
                });
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return BadRequest(new OpenIddictResponse
        {
            Error = Errors.UnsupportedGrantType,
            ErrorDescription = "The specified grant type is not supported."
        });
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/user-info")]
    public IActionResult UserInfo()
    {
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            return Unauthorized();
        }

        var scopes = User.FindFirst("scope")?.Value?.Split(' ') ?? [];

        var claims = new Dictionary<string, string>();

        var subClaim = User.FindFirst(Claims.Subject);
        if (subClaim == null)
        {
            return BadRequest(new { error = "Missing sub claim" });
        }

        claims["sub"] = subClaim.Value;

        if (scopes.Contains("email"))
        {
            var email = User.FindFirst(Claims.Email)?.Value;
            if (email != null)
            {
                claims["email"] = email;
            }
        }

        if (scopes.Contains("profile"))
        {
            var name = User.FindFirst(Claims.Name)?.Value;
            if (name != null)
            {
                claims["name"] = name;
            }

            var givenName = User.FindFirst(Claims.GivenName)?.Value;
            if (givenName != null)
            {
                claims["given_name"] = givenName;
            }

            var familyName = User.FindFirst(Claims.FamilyName)?.Value;
            if (familyName != null)
            {
                claims["family_name"] = familyName;
            }
        }

        return Ok(claims);
    }

    [HttpGet("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}