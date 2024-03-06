using AuthenticationAndAuthorization.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationAndAuthorization.Controllers
{
    [ApiController]
    public class TokenController : ControllerBase
    {
        [Route("api/[controller]/LoginDefaultJwt")]
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

        [Route("api/[controller]/LoginAdminJwt")]
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
    }
}
