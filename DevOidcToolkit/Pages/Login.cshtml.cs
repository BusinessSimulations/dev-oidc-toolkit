namespace DevOidcToolkit.Pages;

using System.ComponentModel.DataAnnotations;

using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;

public class LoginPageModel(SignInManager<DevOidcToolkitUser> signInManager, UserManager<DevOidcToolkitUser> userManager) : PageModel
{
    private readonly SignInManager<DevOidcToolkitUser> _signInManager = signInManager;
    private readonly UserManager<DevOidcToolkitUser> _userManager = userManager;

    [BindProperty]
    public required InputModel Input { get; set; }

    [TempData]
    public required string ErrorMessage { get; set; }

    public required List<SelectListItem> UserEmails { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Display(Name = "Remember me?")]
        public required bool RememberMe { get; set; }
    }

    public void OnGet()
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            ModelState.AddModelError(string.Empty, ErrorMessage);
        }

        var users = _userManager.Users.ToList();

        UserEmails = [.. users.Select(u =>
            new SelectListItem
            {
                Value = u.Email,
                Text = u.Email
            })];
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("/user");

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt");
                return Page();
            }

            await _signInManager.SignInAsync(user, Input.RememberMe);
            return LocalRedirect(returnUrl);
        }

        var users = _userManager.Users.ToList();

        UserEmails = [.. users.Select(u =>
            new SelectListItem
            {
                Value = u.Email,
                Text = u.Email
            })];

        // If we got this far, something failed, redisplay form
        return Page();
    }
}