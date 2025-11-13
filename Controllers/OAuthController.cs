using JwtSumApi.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtSumApi.Controllers
{
    [ApiController]
    [Route("oauth")]
    public class OAuthController : ControllerBase
    {
        private readonly JwtTokenService _jwtService;
        private readonly RoleMappingService _roleService;

        public OAuthController(JwtTokenService jwtService, RoleMappingService roleService)
        {
            _jwtService = jwtService;
            _roleService = roleService;
        }

        [HttpGet("login")]
        public IActionResult Login()
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = "http://localhost:5000/oauth/callback"
            }, "GitHub");
        }

        [HttpGet("callback")]
        public async Task<IActionResult> Callback()
        {
            // ✅ Get the authenticated GitHub principal
            var result = await HttpContext.AuthenticateAsync("GitHub");

            if (!result.Succeeded || result.Principal == null)
            {
                return Unauthorized("GitHub authentication failed.");
            }

            var principal = result.Principal;

            // 🧪 Optional: log claims
            foreach (var claim in principal.Claims)
            {
                Console.WriteLine($"{claim.Type}: {claim.Value}");
            }

            var username = principal.FindFirst(ClaimTypes.Name)?.Value ?? "unknown";
            var role = _roleService.GetRoleForUser(username);

            // ✅ Sign in using cookie scheme
            await HttpContext.SignInAsync("Cookies", principal);

            var token = _jwtService.GenerateToken(username, role);
            return Ok(new { token });
        }


    }
}