using JwtAuthAspNet.Core.Dtos;
using JwtAuthAspNet.Core.Entities;
using JwtAuthAspNet.Core.Interfaces;
using JwtAuthAspNet.Core.OtherObject;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAspNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }



        //ruta por seedinf mis roles to db

        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRolesAsync();
            return Ok(seedRoles);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> register([FromBody] RegisterDto regisetrDto)
        {
            var registerResult = await _authService.RegisterAsync(regisetrDto);

            if(registerResult.IsSucced) return Ok(registerResult);

            return BadRequest(registerResult);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> login([FromBody] LoginDto loginDto)
        {
            //var user = await _userManager.FindByNameAsync(loginDto.UserName);

            //if (user is null) return Unauthorized("Invalid credentials");


            //var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            //if(!isPasswordCorrect) return Unauthorized("Invalid credentials");

            //var userRoles  = await _userManager.GetRolesAsync(user);

            //var authClaims = new List<Claim>
            //{
            //    new Claim(ClaimTypes.Name,user.UserName),
            //    new Claim(ClaimTypes.NameIdentifier,user.Id),
            //    new Claim("JWTID",Guid.NewGuid().ToString()),
            //    new Claim("FirstName",user.FirstName)


            //};

            //foreach(var userRole in userRoles)
            //{
            //    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            //}

            //var token = GenerateNewJsonWebToken(authClaims);

            //return Ok(token);

            var loginResult = await _authService.LoginAsync(loginDto);

            if(loginResult.IsSucced) return Ok(loginResult);

            return Unauthorized(loginResult);

        }

        //private string GenerateNewJsonWebToken(List<Claim> authClaims)
        //{
        //    var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        //    var tokenObject = new JwtSecurityToken(
        //            issuer: _configuration["JWT:ValidIssuer"],
        //            audience : _configuration["JWT:ValidAudience"],
        //            expires: DateTime.Now.AddHours(1),
        //            claims:authClaims,
        //            signingCredentials: new SigningCredentials(authSecret,SecurityAlgorithms.HmacSha256)
        //        );

        //    string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
        //    return token;
        //}


        //rOUTE __>MAKE USER >> ADMIN
        [HttpPost]
        [Route("make-admin")]

        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            //var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            //if (user is null) return BadRequest("Invalid username");

            //await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            //return Ok("User us now an ADMIN");

            var makeAdminResult = await _authService.MakeAdminAsync(updatePermissionDto);

            if (makeAdminResult.IsSucced) return Ok(makeAdminResult);

            return BadRequest(makeAdminResult);
        }
        //Route ->make user -> owner
        [HttpPost]
        [Route("make-owner")]

        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            //var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            //if (user is null) return BadRequest("Invalid username");

            //await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            //return Ok("User us now an OWNER");

            var ownerAdminResult = await _authService.MakeOwnerAsync(updatePermissionDto);
            if (ownerAdminResult.IsSucced) return Ok(ownerAdminResult);

            return BadRequest(ownerAdminResult);
        }
    }
}
