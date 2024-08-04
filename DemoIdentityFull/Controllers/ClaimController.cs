using DemoIdentityFull.Models.ClaimViewModels;
using DemoIdentityFull.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace DemoIdentityFull.Controllers;
public class ClaimController : Controller
{
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public ClaimController(RoleManager<ApplicationRole> roleManager, UserManager<ApplicationUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    [HttpGet]
    public async Task<IActionResult> ManageUserClaims(string UserId)
    {
        //First, fetch the User Details Based on the UserId
        var user = await _userManager.FindByIdAsync(UserId);

        if (user == null)
        {
            //handle if the User is not Exists in the database
            ViewBag.ErrorMessage = $"User with Id = {UserId} cannot be found";
            return View("NotFound");
        }

        //Storing the UserName in the ViewBag for Display Purpose
        ViewBag.UserName = user.UserName;

        //Create UserClaimsViewModel Instance
        var model = new UserClaimsViewModel
        {
            UserId = UserId
        };

        // UserManager service GetClaimsAsync method gets all the current claims of the user
        var existingUserClaims = await _userManager.GetClaimsAsync(user);

        // Loop through each claim we have in our application
        // Call the GetAllClaims Static Method ClaimsStore Class
        foreach (Claim claim in ClaimsStore.GetAllClaims())
        {
            //Create an Instance of UserClaim class
            UserClaim userClaim = new UserClaim
            {
                ClaimType = claim.Type
            };

            // If the user has the claim, set IsSelected property to true, so the checkbox
            // next to the claim is checked on the UI
            if (existingUserClaims.Any(c => c.Type == claim.Type))
            {
                userClaim.IsSelected = true;
            }
            //By default the IsSelected is False, no need to set as false

            //Add the userClaim to UserClaimsViewModel Instance 
            model.Cliams.Add(userClaim);
        }

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel model)
    {
        //First fetch the User Details
        var user = await _userManager.FindByIdAsync(model.UserId);

        if (user == null)
        {
            ViewBag.ErrorMessage = $"User with Id = {model.UserId} cannot be found";
            return View("NotFound");
        }

        // Get all the user existing claims and delete them
        var claims = await _userManager.GetClaimsAsync(user);
        var result = await _userManager.RemoveClaimsAsync(user, claims);

        if (!result.Succeeded)
        {
            ModelState.AddModelError("", "Cannot remove user existing claims");
            return View(model);
        }

        // Add all the claims that are selected on the UI
        var AllSelectedClaims = model.Cliams.Where(c => c.IsSelected)
                    .Select(c => new Claim(c.ClaimType, c.ClaimType))
                    .ToList();

        //If At least 1 Claim is assigned, Any Method will return true
        if (AllSelectedClaims.Any())
        {
            //add a user to multiple claims simultaneously
            result = await _userManager.AddClaimsAsync(user, AllSelectedClaims);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Cannot add selected claims to user");
                return View(model);
            }
        }

        return RedirectToAction("EditUser", "User", new { UserId = model.UserId });
    }

    [HttpGet]
    public async Task<IActionResult> ManageRoleClaims(string RoleId)
    {
        //First, fetch the Role Details Based on the RoleId
        var role = await _roleManager.FindByIdAsync(RoleId);

        if (role == null)
        {
            //handle if the role is not Exists in the database
            ViewBag.ErrorMessage = $"Role with Id = {RoleId} cannot be found";
            return View("NotFound");
        }

        //Storing the Role Name in the ViewBag for Display Purpose
        ViewBag.RoleName = role.Name;

        //Create RoleClaimsViewModel Instance
        var model = new RoleClaimsViewModel
        {
            RoleId = RoleId
        };

        // RoleManager service GetClaimsAsync method gets all the current claims of the role
        var existingRoleClaims = await _roleManager.GetClaimsAsync(role);

        // Loop through each claim we have in our application
        // Call the GetAllClaims Static Method ClaimsStore Class
        foreach (Claim claim in ClaimsStore.GetAllClaims())
        {
            //Create an Instance of RoleClaim class
            RoleClaim roleClaim = new RoleClaim
            {
                ClaimType = claim.Type
            };

            // If the Role has the claim, set IsSelected property to true, so the checkbox
            // next to the claim is checked on the UI
            if (existingRoleClaims.Any(c => c.Type == claim.Type))
            {
                roleClaim.IsSelected = true;
            }
            //By default, the IsSelected is False, no need to set as false

            //Add the roleClaim to RoleClaimsViewModel Instance 
            model.Claims.Add(roleClaim);
        }

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> ManageRoleClaims(RoleClaimsViewModel model)
    {
        //First fetch the Role Details
        var role = await _roleManager.FindByIdAsync(model.RoleId);

        if (role == null)
        {
            ViewBag.ErrorMessage = $"Role with Id = {model.RoleId} cannot be found";
            return View("NotFound");
        }

        // Get all the existing claims of the role
        var claims = await _roleManager.GetClaimsAsync(role);


        for (int i = 0; i < model.Claims.Count; i++)
        {
            Claim claim = new Claim(model.Claims[i].ClaimType, model.Claims[i].ClaimType);

            IdentityResult result;

            if (model.Claims[i].IsSelected && !(claims.Any(c => c.Type == claim.Type)))
            {
                //If IsSelected is true and User is not already in this role, then add the user
                //result = await _userManager.AddToRoleAsync(user, role.Name);
                result = await _roleManager.AddClaimAsync(role, claim);
            }
            else if (!model.Claims[i].IsSelected && claims.Any(c => c.Type == claim.Type))
            {
                //If IsSelected is false and User is already in this role, then remove the user
                result = await _roleManager.RemoveClaimAsync(role, claim);
            }
            else
            {
                //Don't do anything simply continue the loop
                continue;
            }

            //If you add or remove any user, please check the Succeeded of the IdentityResult
            if (result.Succeeded)
            {
                if (i < (model.Claims.Count - 1))
                    continue;
                else
                    return RedirectToAction("EditRole", "Role", new { roleId = model.RoleId });
            }
            else
            {
                ModelState.AddModelError("", "Cannot add or removed selected claims to role");
                return View(model);
            }
        }
        return RedirectToAction("EditRole","Role", new { roleId = model.RoleId });
    }
}
