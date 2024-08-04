using DemoIdentityFull.Models;
using DemoIdentityFull.Models.ManageViewModels;
using DemoIdentityFull.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace DemoIdentityFull.Controllers;

public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ISenderEmail _emailSender;
    private readonly ISMSSender _smsSender;

    public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ISenderEmail emailSender,
        ISMSSender smsSender)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailSender = emailSender;
        _smsSender = smsSender;
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> ChangePassword()
    {
        // First Fetch the User Details
        var user = await _userManager.GetUserAsync(User);

        //Then Check whether the User Already has a Password
        var userHasPassword = await _userManager.HasPasswordAsync(user);

        //If the user has no password, redirect to the AddPassword Action method
        if (!userHasPassword)
        {
            return RedirectToAction("AddPassword", "Manage");
        }

        //If the user has already password, then display the Change Password view
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            //fetch the User Details
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                //If User does not exists, redirect to the Login Page
                return RedirectToAction("Login", "Account");
            }

            // ChangePasswordAsync Method changes the user password
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

            // The new password did not meet the complexity rules or the current password is incorrect.
            // Add these errors to the ModelState and rerender ChangePassword view
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View();
            }

            // Upon successful change password, update the LastPasswordChangedDate
            user.LastPasswordChangedDate = DateTime.Now;
            await _userManager.UpdateAsync(user);

            // Upon successfully changing the password refresh sign-in cookie
            await _signInManager.RefreshSignInAsync(user);

            //Then redirect the user to the ChangePasswordConfirmation view
            return RedirectToAction("ChangePasswordConfirmation", "Manage");
        }

        return View(model);
    }

    [Authorize]
    [HttpGet]
    public IActionResult ChangePasswordConfirmation()
    {
        return View();
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> AddPassword()
    {
        //First Fetch the User Details
        var user = await _userManager.GetUserAsync(User);

        //Then Check whether the User Already has a Password
        var userHasPassword = await _userManager.HasPasswordAsync(user);

        //If the user already has a password, redirect to the ChangePassword Action method
        if (userHasPassword)
        {
            return RedirectToAction("ChangePassword", "Account");
        }

        //If the user has no password, then display the Add Password view
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> AddPassword(AddPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Unable to Load User.");
                return View();
            }

            //Call the AddPasswordAsync method to set the new password without old password
            var result = await _userManager.AddPasswordAsync(user, model.NewPassword);

            // Handle the failure scenario
            if (!result.Succeeded)
            {
                //fetch all the error messages and display on the view
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View();
            }

            // Upon successful Add password to External Account, update the LastPasswordChangedDate
            user.LastPasswordChangedDate = DateTime.Now;
            await _userManager.UpdateAsync(user);

            // Handle Success Scenario
            // refresh the authentication cookie to store the updated user information
            await _signInManager.RefreshSignInAsync(user);

            //redirecting to the AddPasswordConfirmation action method
            return RedirectToAction("AddPasswordConfirmation", "Manage");
        }

        return View();
    }

    [Authorize]
    [HttpGet]
    public IActionResult AddPasswordConfirmation()
    {
        return View();
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> ConfirmPhoneNumber()
    {
        //If the User already provided the Mobile while registering, we need to show that mobile number,
        //else we need to display empty and allow the user to add or update the mobile number

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        ConfirmPhoneNumberViewModel model = new ConfirmPhoneNumberViewModel()
        {
            PhoneNumber = user.PhoneNumber
        };

        return View(model);
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> SendPhoneVerificationCode(ConfirmPhoneNumberViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            //Generate the Token
            var token = await _userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);

            // Code to send the token via SMS 
            var result = await _smsSender.SendSmsAsync(model.PhoneNumber, token);

            if (result)
            {
                // Save or pass the phone number for later verification
                TempData["PhoneNumber"] = model.PhoneNumber;

                // Redirect to verification view
                return RedirectToAction("VerifyPhoneNumber", "Account");
        }
        else
        {
            ViewBag.ErrorTitle = "Unable to send SMS";
            ViewBag.ErrorMessage = "Please try after some time";
            return RedirectToAction("Error");
        }
    }

    return View(model);
}

    [Authorize]
    [HttpGet]
    public IActionResult VerifyPhoneNumber()
    {
        TempData["PhoneNumber"] = TempData["PhoneNumber"] as string;
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> VerifyPhoneNumber(string Token)
    {
        var PhoneNumber = TempData["PhoneNumber"] as string;
        var user = await _userManager.GetUserAsync(User);

        var result = await _userManager.VerifyChangePhoneNumberTokenAsync(user, Token, PhoneNumber);

        if (result)
        {
            // Update user's PhoneNumber and PhoneNumberConfirmed
            user.PhoneNumber = PhoneNumber;
            user.PhoneNumberConfirmed = true;
            await _userManager.UpdateAsync(user);

            // Redirect to success page or show success message
            return View("PhoneVerificationSuccessful");
        }
        else
        {
            // Handle verification failure
            ViewBag.ErrorTitle = "Verification Failed";
            ViewBag.ErrorMessage = "Either the Token Expired or you entered an invalid token";
            return RedirectToAction("Error");
        }
    }

    [Authorize]
    [HttpGet]
    public IActionResult PhoneVerificationSuccessful()
    {
        return View();
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> ManageTwoFactorAuthentication()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        //First, we need to check whether the User Phone and Email is confirmed or not
        if (!user.PhoneNumberConfirmed && !user.EmailConfirmed)
        {
            ViewBag.ErrorTitle = "You cannot Enable/Disable Two Factor Authentication";
            ViewBag.ErrorMessage = "Your Phone Number and Email Not Yet Confirmed";
            return View("Error");
        }

        string Message;
        if (user.TwoFactorEnabled)
        {
            Message = "Disable 2FA";
        }
        else
        {
            Message = "Enable 2FA";
        }

        //Generate the Two Factor Authentication Token
        var TwoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultPhoneProvider);

        //Send the Token to user Mobile Number and Email Id

        //Sending SMS
        var result = await _smsSender.SendSmsAsync(user.PhoneNumber, $"Your Token to {Message} is {TwoFactorToken}");

        //Sending Email
        await _emailSender.SendEmailAsync(user.Email, Message, $"Your Token to {Message} is {TwoFactorToken}", false);

        return View(); // View for the user to enter the token
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ManageTwoFactorAuthentication(string Token)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var result = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultPhoneProvider, Token);
        if (result)
        {
            // Token is valid
            if (user.TwoFactorEnabled)
            {
                user.TwoFactorEnabled = false;
                ViewBag.Message = "You have Sucessfully Disabled Two Factor Authentication";
            }
            else
            {
                user.TwoFactorEnabled = true;
                ViewBag.Message = "You have Sucessfully Enabled Two Factor Authentication";
            }

            await _userManager.UpdateAsync(user);

            // Redirect to success page 
            return View("TwoFactorAuthenticationSuccessful");
        }
        else
        {
            // Handle invalid token
            ViewBag.ErrorTitle = "Unable to Enable/Disable Two Factor Authentication";
            ViewBag.ErrorMessage = "Either the Token is Expired or you entered some wrong information";
            return View("Error");
        }
    }
}
