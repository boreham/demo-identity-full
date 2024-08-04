using DemoIdentityFull.Models;
using DemoIdentityFull.Models.AccountViewModels;
using DemoIdentityFull.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace DemoIdentityFull.Controllers;
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ISenderEmail _emailSender;
    private readonly ISMSSender _smsSender;

    public AccountController(
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

    // Register GET method
    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    // Register POST method
    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            // Copy data from RegisterViewModel to ApplicationUser
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber,
                LastPasswordChangedDate = DateTime.Now
            };

            // Store user data in AspNetUsers database table
            var result = await _userManager.CreateAsync(user, model.Password);

            // If user is successfully created, sign-in the user using
            // SignInManager and redirect to index action of HomeController
            if (result.Succeeded)
            {
                //Then send the Confirmation Email to the User
                await SendConfirmationEmail(model.Email, user);

                // If the user is signed in and in the Admin role, then it is
                // the Admin user that is creating a new user. 
                // So redirect the Admin user to ListUsers action of Administration Controller
                if (_signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                {
                    return RedirectToAction("ListUsers", "User");
                }

                //If it is not Admin user, then redirect the user to RegistrationSuccessful View
                return View("RegistrationSuccessful");
            }

            // If there are any errors, add them to the ModelState object
            // which will be displayed by the validation summary tag helper
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return View(model);
    }

    // Login GET method
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string ReturnUrl = null)
    {
        LoginViewModel model = new LoginViewModel
        {
            ReturnUrl = ReturnUrl,
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
        };
        return View(model);
    }

    // Login POST method
    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginViewModel model, string ReturnUrl)
    {
        //If Model Login Failed, we also need to show the External Login Providers 
        model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (ModelState.IsValid)
        {
            //First Fetch the User Details by Email Id
            var user = await _userManager.FindByEmailAsync(model.Email);

            //Then Check if User Exists, EmailConfirmed and Password Is Valid
            //CheckPasswordAsync: Returns a flag indicating whether the given password is valid for the specified user.
            if (user != null && !user.EmailConfirmed &&
                        (await _userManager.CheckPasswordAsync(user, model.Password)))
            {
                ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                return View(model);
            }

            // The last boolean parameter lockoutOnFailure indicates if the account should be locked on failed login attempt. 
            // On every failed login attempt AccessFailedCount column value in AspNetUsers table is incremented by 1. 
            // When the AccessFailedCount reaches the configured MaxFailedAccessAttempts which in our case is 5,
            // the account will be locked and LockoutEnd column is populated.
            // After the account is lockedout, even if we provide the correct username and password,
            // PasswordSignInAsync() method returns Lockedout result and
            // the login will not be allowed for the duration the account is locked.
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                if (user?.LastPasswordChangedDate.AddDays(90) < DateTime.Now)
                {
                    // Password has expired
                    // Redirect user to change password page
                    return View("PasswordExpired");
                }
                // Handle successful login
                // Check if the ReturnUrl is not null and is a local URL
                if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
                {
                    return Redirect(ReturnUrl);
                }
                else
                {
                    // Redirect to default page
                    return RedirectToAction("Index", "Home");
                }
            }
            if (result.RequiresTwoFactor)
            {
                // Handle two-factor authentication case
                // Generate a 2FA token, send that token to user Email and Phone Number
                // and redirect to the 2FA verification view
                var TwoFactorAuthenticationToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                //Sending SMS
                await _smsSender.SendSmsAsync(user.PhoneNumber, $"Your 2FA Token is {TwoFactorAuthenticationToken}");

                //Sending Email
                await _emailSender.SendEmailAsync(user.Email, "2FA Token", $"Your 2FA Token is {TwoFactorAuthenticationToken}", false);

                return RedirectToAction("VerifyTwoFactorToken", "Account", new { model.Email, ReturnUrl, model.RememberMe, TwoFactorAuthenticationToken });
            }
            if (result.IsLockedOut)
            {
                //It's important to inform users when their account is locked.
                //This can be done through the UI or by sending an email notification.
                await SendAccountLockedEmail(model.Email);
                return View("AccountLocked");
            }
            else
            {
                // Handle failure
                // Get the number of attempts left
                var attemptsLeft = _userManager.Options.Lockout.MaxFailedAccessAttempts - await _userManager.GetAccessFailedCountAsync(user);

                ModelState.AddModelError(string.Empty, $"Invalid Login Attempt. Remaining Attempts : {attemptsLeft}");
                return View(model);
            }
        }

        // If we got this far, something failed, redisplay form
        return View(model);
    }

    // Logout POST method
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("index", "home");
    }

    // Email validation is available
    [AllowAnonymous]
    [HttpPost]
    [HttpGet]
    public async Task<IActionResult> IsEmailAvailable(string Email)
    {
        //Check If the Email Id is Already in the Database
        var user = await _userManager.FindByEmailAsync(Email);

        if (user == null)
        {
            return Json(true);
        }
        else
        {
            return Json($"Email {Email} is already in use.");
        }
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult ExternalLogin(string provider, string returnUrl)
    {
        //This call will generate a URL that directs to the ExternalLoginCallback action method in the Account controller
        //with a route parameter of ReturnUrl set to the value of returnUrl.
        var redirectUrl = Url.Action(action: "ExternalLoginCallback", controller: "Account", values: new { ReturnUrl = returnUrl });
        // Configure the redirect URL, provider and other properties
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        //This will redirect the user to the external provider's login page
        return new ChallengeResult(provider, properties);
    }

    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl, string remoteError)
    {
        returnUrl = returnUrl ?? Url.Content("~/");

        LoginViewModel loginViewModel = new LoginViewModel
        {
            ReturnUrl = returnUrl,
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
        };

        if (remoteError != null)
        {
            ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");

            return View("Login", loginViewModel);
        }

        // Get the login information about the user from the external login provider
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ModelState.AddModelError(string.Empty, "Error loading external login information.");

            return View("Login", loginViewModel);
        }

        // Email Confirmation Section
        // Get the email claim from external login provider (Google, Facebook etc)
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        ApplicationUser user;

        if (email != null)
        {
            // Find the user
            user = await _userManager.FindByEmailAsync(email);

            // If the user exists in our database and email is not confirmed,
            // display login view with validation error
            if (user != null && !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                return View("Login", loginViewModel);
            }
        }

        // If the user already has a login (i.e., if there is a record in AspNetUserLogins table)
        // then sign-in the user with this external login provider
        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
            info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

        if (signInResult.Succeeded)
        {
            return LocalRedirect(returnUrl);
        }

        // If there is no record in AspNetUserLogins table, the user may not have a local account
        else
        {
            if (email != null)
            {
                // Create a new user without password if we do not have a user already
                user = await _userManager.FindByEmailAsync(email);

                if (user == null)
                {
                    user = new ApplicationUser
                    {
                        UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                        FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
                        LastName = info.Principal.FindFirstValue(ClaimTypes.Surname),
                    };

                    //This will create a new user into the AspNetUsers table without password
                    await _userManager.CreateAsync(user);
                }

                // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                await _userManager.AddLoginAsync(user, info);

                //Then send the Confirmation Email to the User
                await SendConfirmationEmail(email, user);

                //Redirect the user to the Successful Registration Page
                return View("RegistrationSuccessful");
            }

            // If we cannot find the user email we cannot continue
            ViewBag.ErrorTitle = $"Email claim not received from: {info.LoginProvider}";
            ViewBag.ErrorMessage = "Please contact support on info@example.com";

            return View("Error");
        }
    }

    private async Task SendConfirmationEmail(string email, ApplicationUser user)
    {
        //Generate the Token
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        //Build the Email Confirmation Link which must include the Callback URL
        var ConfirmationLink = Url.Action("ConfirmEmail", "Account",
        new { UserId = user.Id, Token = token }, protocol: HttpContext.Request.Scheme);

        //Send the Confirmation Email to the User Email Id
        await _emailSender.SendEmailAsync(email, "Confirm Your Email", $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(ConfirmationLink)}'>clicking here</a>.", true);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string UserId, string Token)
    {
        if (UserId == null || Token == null)
        {
            ViewBag.Message = "The link is Invalid or Expired";
        }

        //Find the User By Id
        var user = await _userManager.FindByIdAsync(UserId);
        if (user == null)
        {
            ViewBag.ErrorMessage = $"The User ID {UserId} is Invalid";
            return View("NotFound");
        }

        //Call the ConfirmEmailAsync Method which will mark the Email as Confirmed
        var result = await _userManager.ConfirmEmailAsync(user, Token);
        if (result.Succeeded)
        {
            ViewBag.Message = "Thank you for confirming your email";
            return View();
        }

        ViewBag.Message = "Email cannot be confirmed";
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResendConfirmationEmail(bool IsResend = true)
    {
        if (IsResend)
        {
            ViewBag.Message = "Resend Confirmation Email";
        }
        else
        {
            ViewBag.Message = "Send Confirmation Email";
        }
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendConfirmationEmail(string Email)
    {
        var user = await _userManager.FindByEmailAsync(Email);
        if (user == null || await _userManager.IsEmailConfirmedAsync(user))
        {
            // Handle the situation when the user does not exist or Email already confirmed.
            // For security, don't reveal that the user does not exist or Email is already confirmed
            return View("ConfirmationEmailSent");
        }

        //Then send the Confirmation Email to the User
        await SendConfirmationEmail(Email, user);

        return View("ConfirmationEmailSent");
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            // Find the user by email
            var user = await _userManager.FindByEmailAsync(model.Email);

            // If the user is found AND Email is confirmed
            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                await SendForgotPasswordEmail(user.Email, user);

                // Send the user to Forgot Password Confirmation view
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // To avoid account enumeration and brute force attacks, don't
            // reveal that the user does not exist or is not confirmed
            return RedirectToAction("ForgotPasswordConfirmation", "Account");
        }

        return View(model);
    }

    [AllowAnonymous]
    public ActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    private async Task SendForgotPasswordEmail(string email, ApplicationUser user)
    {
        // Generate the reset password token
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        //save the token into the AspNetUserTokens database table
        await _userManager.SetAuthenticationTokenAsync(user, "ResetPassword", "ResetPasswordToken", token);

        // Build the password reset link which must include the Callback URL
        // Build the password reset link
        var passwordResetLink = Url.Action("ResetPassword", "Account",
                new { Email = email, Token = token }, protocol: HttpContext.Request.Scheme);

        //Send the Confirmation Email to the User Email Id
        await _emailSender.SendEmailAsync(email, "Reset Your Password", $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(passwordResetLink)}'>clicking here</a>.", true);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string Token, string Email)
    {
        // If password reset token or email is null, most likely the
        // user tried to tamper the password reset link
        if (Token == null || Email == null)
        {
            ViewBag.ErrorTitle = "Invalid Password Reset Token";
            ViewBag.ErrorMessage = "The Link is Expired or Invalid";
            return View("Error");
        }
        else
        {
            ResetPasswordViewModel model = new ResetPasswordViewModel();
            model.Token = Token;
            model.Email = Email;
            return View(model);
        }
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            // Find the user by email
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null)
            {
                // reset the user password
                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                if (result.Succeeded)
                {
                    // Upon successful password reset, update the LastPasswordChangedDate
                    user.LastPasswordChangedDate = DateTime.Now;
                    await _userManager.UpdateAsync(user);

                    // Upon successful password reset and if the account is lockedout,
                    // set the account lockout end date to current UTC date time, 
                    // so the user can login with the new password
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                    }

                    //Once the Password is Reset, remove the token from the database if you are storing the token
                    await _userManager.RemoveAuthenticationTokenAsync(user, "ResetPassword", "ResetPasswordToken");
                    return RedirectToAction("ResetPasswordConfirmation", "Account");
                }

                // Display validation errors. For example, password reset token already
                // used to change the password or password complexity rules not met
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View(model);
            }

            // To avoid account enumeration and brute force attacks, don't
            // reveal that the user does not exist
            return RedirectToAction("ResetPasswordConfirmation", "Account");
        }
        // Display validation errors if model state is not valid
        return View(model);
    }

    [AllowAnonymous]
    public ActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    private async Task SendAccountLockedEmail(string email)
    {
        //Send the Confirmation Email to the User Email Id
        await _emailSender.SendEmailAsync(email, "Account Locked", "Your Account is Locked Due to Multiple Invalid Attempts.", false);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult VerifyTwoFactorToken(string Email, string ReturnUrl, bool RememberMe, string TwoFactorAuthenticationToken)
    {
        VerifyTwoFactorTokenViewModel model = new VerifyTwoFactorTokenViewModel()
        {
            RememberMe = RememberMe,
            Email = Email,
            ReturnUrl = ReturnUrl,
            Token = TwoFactorAuthenticationToken
        };

        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyTwoFactorToken(VerifyTwoFactorTokenViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
            return View(model);
        }

        // Validate the 2FA token
        var result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.TwoFactorCode);
        if (result)
        {
            // Sign in the user and redirect
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

            // Check if the ReturnUrl is not null and is a local URL
            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }
            else
            {
                // Redirect to default page
                return RedirectToAction("Index", "Home");
            }
        }

        ModelState.AddModelError(string.Empty, "Invalid verification code.");
        return View(model);
    }
}
