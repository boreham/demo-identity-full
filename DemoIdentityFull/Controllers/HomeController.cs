using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DemoIdentityFull.Controllers;
public class HomeController : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View();
    }

    [AllowAnonymous]
    public IActionResult NonSecureMethod()
    {
        return View();
    }

    [Authorize]
    public IActionResult SecureMethod()
    {
        return View();
    }
}
