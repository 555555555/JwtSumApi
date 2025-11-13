using JwtSumApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtSumApi.Controllers
{

    [ApiController]
    [Route("api/sum")]
    public class SumController : ControllerBase
    {
        
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult Sum([FromBody] SumRequest request)
        {
            var scheme = HttpContext.User.Identity?.AuthenticationType;
            var role = HttpContext.User.FindFirst(ClaimTypes.Role)?.Value;

            Console.WriteLine($"Auth Scheme: {scheme}, Role: {role}");

            var result = request.A + request.B;
            return Ok(new { result });
        }
    }
}
