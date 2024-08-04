using System.ComponentModel.DataAnnotations;

namespace DemoIdentityFull.Models.RoleViewModels;

public class CreateRoleViewModel
{
    [Required]
    [Display(Name = "Role")]
    public string RoleName { get; set; }

    public string Description { get; set; }
}
