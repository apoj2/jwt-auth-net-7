using JwtAuthAspNet.Core.OtherObject;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthAspNet.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };


        [HttpGet]
        [Route("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }


        [HttpGet]
        [Route("GetUsersRoles")]
        [Authorize(Roles = StaticUserRoles.USER)]
        public IActionResult GetUser()
        {
            return Ok(Summaries);
        }

        [HttpGet]
        [Route("GetAdminsRoles")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public IActionResult GetAdmin()
        {
            return Ok(Summaries);
        }

        [HttpGet]
        [Route("GetOwnersRoles")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public IActionResult GetOwner()
        {
            return Ok(Summaries);
        }
    }
}
