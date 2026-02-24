using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;

namespace DevOidcToolkit.Pages;

public class ClientsModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly DevOidcToolkitContext _context;

    public ClientsModel(IOpenIddictApplicationManager applicationManager, DevOidcToolkitContext context)
    {
        _applicationManager = applicationManager;
        _context = context;
    }

    public List<OpenIddictEntityFrameworkCoreApplication> Clients { get; set; } = [];
    public string? SuccessMessage { get; set; }
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public InputModel? Input { get; set; }

    public class InputModel
    {
        public string ClientId { get; set; } = "";
        public string ClientSecret { get; set; } = "";
        public string RedirectUris { get; set; } = "";
        public string PostLogoutRedirectUris { get; set; } = "";
    }

    public async Task OnGetAsync()
    {
        Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid || Input == null)
        {
            Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.ClientId))
        {
            ModelState.AddModelError("Input.ClientId", "Client ID is required");
            Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.ClientSecret))
        {
            ModelState.AddModelError("Input.ClientSecret", "Client Secret is required");
            Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
            return Page();
        }

        // Check if client already exists
        var existingClient = await _applicationManager.FindByClientIdAsync(Input.ClientId);
        if (existingClient != null)
        {
            ErrorMessage = $"Client with ID '{Input.ClientId}' already exists";
            Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
            return Page();
        }

        try
        {
            var clientApp = new OpenIddictApplicationDescriptor()
            {
                ClientId = Input.ClientId,
                ClientSecret = Input.ClientSecret,
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Email
                }
            };

            if (!string.IsNullOrWhiteSpace(Input.RedirectUris))
            {
                var redirectUris = Input.RedirectUris.Split(',').Select(uri => uri.Trim()).Where(uri => !string.IsNullOrWhiteSpace(uri));
                foreach (var uri in redirectUris)
                {
                    try
                    {
                        clientApp.RedirectUris.Add(new Uri(uri));
                    }
                    catch (UriFormatException)
                    {
                        throw new InvalidOperationException($"Invalid redirect URI: {uri}");
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(Input.PostLogoutRedirectUris))
            {
                var postLogoutUris = Input.PostLogoutRedirectUris.Split(',').Select(uri => uri.Trim()).Where(uri => !string.IsNullOrWhiteSpace(uri));
                foreach (var uri in postLogoutUris)
                {
                    try
                    {
                        clientApp.PostLogoutRedirectUris.Add(new Uri(uri));
                    }
                    catch (UriFormatException)
                    {
                        throw new InvalidOperationException($"Invalid post-logout redirect URI: {uri}");
                    }
                }
            }

            await _applicationManager.CreateAsync(clientApp);
            SuccessMessage = $"Client '{Input.ClientId}' created successfully";
            Input = new InputModel();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to create client: {ex.Message}";
        }

        Clients = await _context.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync();
        return Page();
    }
}