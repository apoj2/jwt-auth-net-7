﻿using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet.Core.Dtos
{
    public class RegisterDto
    {
        [Required(ErrorMessage ="Username is required")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
        [Required(ErrorMessage = "FisrtName is required")]
        public string FisrtName { get; set; }
        [Required(ErrorMessage = "LastName is required")]
        public string LastName { get; set; }
    }
}
