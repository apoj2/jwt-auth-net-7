using JwtAuthAspNet.Core.Dtos;
using JwtAuthAspNet.Core.Entities;
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
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //ruta por seedinf mis roles to db

        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if(isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return Ok("Role seedinf is already done");
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return Ok("Role Seedinf Done successfuly");
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> register([FromBody] RegisterDto regisetrDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(regisetrDto.UserName);

            if (isExistsUser != null) return BadRequest("Username already exists");

            User newUser = new User()
            {
                FirstName = regisetrDto.FisrtName,
                LastName = regisetrDto.LastName,
                Email = regisetrDto.Email,
                UserName = regisetrDto.UserName,
                SecurityStamp= Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser,regisetrDto.Password);

            if(!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Beacuese: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "#" + error.Description;
                }     
                return BadRequest(errorString);
            }
            //ADD  default user role to al users
            await _userManager.AddToRoleAsync(newUser,StaticUserRoles.USER);
            return Ok("User created successfully");
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> login([FromBody] LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user is null) return Unauthorized("Invalid credentials");


            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if(!isPasswordCorrect) return Unauthorized("Invalid credentials");

            var userRoles  = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("JWTID",Guid.NewGuid().ToString()),
                new Claim("FirstName",user.FirstName)


            };

            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);

        }

        private string GenerateNewJsonWebToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience : _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims:authClaims,
                    signingCredentials: new SigningCredentials(authSecret,SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }


        //rOUTE __>MAKE USER >> ADMIN
        [HttpPost]
        [Route("make-admin")]

        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null) return BadRequest("Invalid username");

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return Ok("User us now an ADMIN");
        }
        //Route ->make user -> owner
        [HttpPost]
        [Route("make-owner")]

        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null) return BadRequest("Invalid username");

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return Ok("User us now an OWNER");
        }
    }
}
