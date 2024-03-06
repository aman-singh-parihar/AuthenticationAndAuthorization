using AuthenticationAndAuthorization.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthenticationAndAuthorization.Controllers
{
    public class CookieController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Index(User user)
        {
            var claims = new List<Claim>
            {
                new (ClaimTypes.Name, user.Username ?? string.Empty),
                new ("CompanyName", "CompanyIT"),
                new (ClaimTypes.Role, "User")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = user.RememberMe,
                    AllowRefresh = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(1)
                });
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> LoginAdminCookie([FromBody] User user)
        {
            var claims = new List<Claim>
            {
                new (ClaimTypes.Name, user.Username ?? string.Empty),
                new ("CompanyName", "CompanyIT"),
                new (ClaimTypes.Role, "Admin")
            };

            var identity = new ClaimsIdentity(claims, "AdminCookie");

            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                "AdminCookie",
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = user.RememberMe,
                    AllowRefresh = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(1)
                });
            return Ok();
        }
    }
}
