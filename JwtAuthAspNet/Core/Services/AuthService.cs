using JwtAuthAspNet.Core.Dtos;
using JwtAuthAspNet.Core.Entities;
using JwtAuthAspNet.Core.Interfaces;
using JwtAuthAspNet.Core.OtherObject;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAspNet.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthService(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            AuthServiceResponseDto result = new AuthServiceResponseDto();

            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user is null)
            {
                result.IsSucced = false ;
                result.Message = "Invalid credentials";
                return result;
            }


            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect) 
            {
                result.IsSucced = false;
                result.Message = "Invalid credentials";
                return result;
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("JWTID",Guid.NewGuid().ToString()),
                new Claim("FirstName",user.FirstName)


            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);
            result.IsSucced = true;
            result.Message = token;
            return result;
        }

        private string GenerateNewJsonWebToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            AuthServiceResponseDto result = new AuthServiceResponseDto();

            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
            {
                result.IsSucced = true;
                result.Message = "Invalid username";
                return result;
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            result.IsSucced = true;
            result.Message = "User us now an ADMIN";
            return result;
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            AuthServiceResponseDto result = new AuthServiceResponseDto();

            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null) 
            {
                    result.IsSucced = true;
                    result.Message = "Invalid username";
                    return result;
            }

                await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            result.IsSucced = true;
            result.Message = "User us now an OWNER";
            return result;
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            AuthServiceResponseDto result = new AuthServiceResponseDto();

            var isExistsUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExistsUser != null)
            {
                result.IsSucced = true;
                result.Message = "Username already exists";
                return result;
            }

            User newUser = new User()
            {
                FirstName = registerDto.FisrtName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Beacuese: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "#" + error.Description;
                }
                
                result.IsSucced = false;
                result.Message = errorString;
                return result;
            }
            //ADD  default user role to al users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            result.IsSucced = true;
            result.Message = "User created successfully";
            return result;
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            AuthServiceResponseDto result = new AuthServiceResponseDto();

            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
        

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                result.IsSucced = true;
                result.Message = "Roles seeding is Already Done";
                return result;
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            result.IsSucced = true;
            result.Message = "Role Seeding Done successfuly";

            return result;
        }
    }
}
