namespace DevOidcToolkit.Infrastructure.Database;

using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class DevOidcToolkitContext(DbContextOptions<DevOidcToolkitContext> options) : IdentityDbContext<DevOidcToolkitUser>(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}

public class DevOidcToolkitUser : IdentityUser
{
    [Required] public required string FirstName { get; set; }
    [Required] public required string LastName { get; set; }
}