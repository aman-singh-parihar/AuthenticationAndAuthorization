using AuthenticationAndAuthorization.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace AuthenticationAndAuthorization.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [Authorize]
        public IActionResult GetWithAny()
        {
            return Ok(new { Message = $"Hello to Code Maze {GetUsername()}" });
        }

        public IActionResult GetWithSecondJwt()
        {
            return Ok(new { Message = $"Hello to Code Maze {GetUsername()}" });
        }
        private string? GetUsername()
        {
            return HttpContext.User.Claims
                .Where(x => x.Type == ClaimTypes.Name)
                .Select(x => x.Value)
                .FirstOrDefault();
        }
        public IActionResult GetWithCookie()
        {
            var userName = HttpContext.User.Claims
                    .Where(x => x.Type == ClaimTypes.Name)
                    .Select(x => x.Value)
                    .FirstOrDefault();
            return Content($"<p>Hello to Code Maze {userName}</p>");
        }
        public IActionResult Index()
        {
            return View();
        }
    }
}
