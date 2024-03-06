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

    }
}
