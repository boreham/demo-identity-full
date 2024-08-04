using Microsoft.AspNetCore.Identity;

namespace DemoIdentityFull.Models;

public class ApplicationRole : IdentityRole
{
    public string Description { get; set; }
}
