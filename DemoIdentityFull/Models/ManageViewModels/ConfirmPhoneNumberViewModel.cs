using System.ComponentModel.DataAnnotations;

namespace DemoIdentityFull.Models.ManageViewModels;

public class ConfirmPhoneNumberViewModel
{
    [Phone(ErrorMessage = "Please Enter a Valid Phone Number")]
    [Required(ErrorMessage = "Please Enter Phone Number")]
    [Display(Name = "Phone Number")]
    public string PhoneNumber { get; set; }
}
