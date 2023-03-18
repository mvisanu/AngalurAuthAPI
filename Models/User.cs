﻿using System.ComponentModel.DataAnnotations;

namespace AngularAuthAPI.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        public string FirstName { get; set; } = string.Empty;       
        public string LastName { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string Useranme { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string Token { get; set; } = string.Empty;

        public string Role { get; set; } = string.Empty;
    }
}