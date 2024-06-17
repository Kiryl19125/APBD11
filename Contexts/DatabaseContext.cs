using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWT.Contexts;

public class DatabaseContext : IdentityDbContext<IdentityUser>
{
    public DatabaseContext(DbContextOptions<DatabaseContext> options)
        : base(options)
    {
    }
   
    public DbSet<RefreshModel> RefreshTokens { get; set; }
}