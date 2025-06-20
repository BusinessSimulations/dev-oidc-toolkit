namespace DevOidcToolkit.Pages;

using DevOidcToolkit.Infrastructure.Database;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

[Authorize]
public class LogOutPageModel(SignInManager<DevOidcToolkitUser> signInManager) : PageModel
{
    private readonly SignInManager<DevOidcToolkitUser> _signInManager = signInManager;

    public async Task<IActionResult> OnPost()
    {
        await _signInManager.SignOutAsync();

        return Redirect("/");
    }
}