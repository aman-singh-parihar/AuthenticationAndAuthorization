using AuthenticationAndAuthorization.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationAndAuthorization.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Check() 
        {
            return Ok(new { Status = "Success" });
        }
        [HttpPost]
        public IActionResult LoginDefaultJwt([FromBody] User user)
        {
            var claims = new List<Claim>
            {
                new (ClaimTypes.Name, user.Username ?? string.Empty),
                new ("CompanyName", "CompanyIT"),
                new (ClaimTypes.Role, "User")
            };

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKeyForCreatingTheJWTAuthenticationTokenForUserAuthentication@1"));

            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokenOptions = new JwtSecurityToken(
                issuer: "https://localhost:7149/",
                audience: "https://localhost:7149/",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: signinCredentials
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
            return Ok(new { Token = tokenString });
        }

        [HttpPost]
        public IActionResult LoginAdminJwt([FromBody] User user)
        {
            var claims = new List<Claim>
            {
                new (ClaimTypes.Name, user.Username ?? string.Empty),
                new ("CompanyName", "CompanyIT"),
                new (ClaimTypes.Role, "User")
            };

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKeyForCreatingTheJWTAuthenticationTokenForUserAuthentication@2"));

            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokenOptions = new JwtSecurityToken(
                issuer: "https://localhost:7149/",
                audience: "https://localhost:7149/",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: signinCredentials
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
            return Ok(new { Token = tokenString });
        }

        [HttpPost]
        public async Task<IActionResult> LoginDefaultCookie([FromBody] User user)
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
            return Ok();
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
