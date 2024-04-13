using Microsoft.AspNetCore.Identity;

namespace JwtAuthAspNet.Core.Entities
{
    public class User:IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        
    }
}
