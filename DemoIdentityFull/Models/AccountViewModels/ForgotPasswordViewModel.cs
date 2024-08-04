using System.ComponentModel.DataAnnotations;

namespace DemoIdentityFull.Models.AccountViewModels;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
