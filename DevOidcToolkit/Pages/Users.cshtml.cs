using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace DevOidcToolkit.Pages;

public class UsersModel : PageModel
{
    private readonly UserManager<DevOidcToolkitUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public UsersModel(UserManager<DevOidcToolkitUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public List<DevOidcToolkitUser> Users { get; set; } = [];
    public string? SuccessMessage { get; set; }
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public InputModel? Input { get; set; }

    public class InputModel
    {
        public string Email { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string? Roles { get; set; }
    }

    public async Task OnGetAsync()
    {
        Users = await _userManager.Users.ToListAsync();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid || Input == null)
        {
            Users = await _userManager.Users.ToListAsync();
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.Email))
        {
            ModelState.AddModelError("Input.Email", "Email is required");
            Users = await _userManager.Users.ToListAsync();
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.FirstName))
        {
            ModelState.AddModelError("Input.FirstName", "First name is required");
            Users = await _userManager.Users.ToListAsync();
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.LastName))
        {
            ModelState.AddModelError("Input.LastName", "Last name is required");
            Users = await _userManager.Users.ToListAsync();
            return Page();
        }

        var user = new DevOidcToolkitUser
        {
            Email = Input.Email,
            UserName = Input.Email,
            FirstName = Input.FirstName,
            LastName = Input.LastName,
            EmailConfirmed = true,
        };

        var result = await _userManager.CreateAsync(user);

        if (result.Succeeded)
        {
            var rolesToAssign = new List<string>();

            if (!string.IsNullOrWhiteSpace(Input.Roles))
            {
                rolesToAssign = Input.Roles.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
            }

            if (rolesToAssign.Any())
            {
                var failedRoles = new List<string>();

                foreach (var roleToAssign in rolesToAssign)
                {
                    // Create role if it doesn't exist
                    if (!await _roleManager.RoleExistsAsync(roleToAssign))
                    {
                        var createRoleResult = await _roleManager.CreateAsync(new IdentityRole(roleToAssign));
                        if (!createRoleResult.Succeeded)
                        {
                            failedRoles.Add($"{roleToAssign} (creation failed)");
                            continue;
                        }
                    }

                    // Assign role to user
                    var roleResult = await _userManager.AddToRoleAsync(user, roleToAssign);
                    if (!roleResult.Succeeded)
                    {
                        failedRoles.Add($"{roleToAssign} (assignment failed)");
                    }
                }

                if (failedRoles.Any())
                {
                    ErrorMessage = $"User created but failed with roles: {string.Join(", ", failedRoles)}";
                }
                else
                {
                    SuccessMessage = $"User {Input.Email} created successfully with roles: {string.Join(", ", rolesToAssign)}";
                }
            }
            else
            {
                SuccessMessage = $"User {Input.Email} created successfully";
            }
            Input = new InputModel();
        }
        else
        {
            ErrorMessage = string.Join(", ", result.Errors.Select(e => e.Description));
        }

        Users = await _userManager.Users.ToListAsync();
        return Page();
    }
}