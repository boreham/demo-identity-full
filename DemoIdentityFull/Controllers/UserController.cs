using DemoIdentityFull.Models;
using DemoIdentityFull.Models.UserViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DemoIdentityFull.Controllers;

[Authorize(Roles = "Admin")]
public class UserController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpGet]
    public IActionResult ListUsers()
    {
        var users = _userManager.Users;
        return View(users);
    }

    [HttpGet]
    public async Task<IActionResult> EditUser(string UserId)
    {
        //First Fetch the User Details by UserId
        var user = await _userManager.FindByIdAsync(UserId);

        //Check if User Exists in the Database
        if (user == null)
        {
            ViewBag.ErrorMessage = $"User with Id = {UserId} cannot be found";
            return View("NotFound");
        }

        // GetClaimsAsync retunrs the list of user Claims
        var userClaims = await _userManager.GetClaimsAsync(user);

        // GetRolesAsync returns the list of user Roles
        var userRoles = await _userManager.GetRolesAsync(user);

        //Store all the information in the EditUserViewModel instance
        var model = new EditUserViewModel
        {
            Id = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Claims = userClaims.Select(c => c.Value).ToList(),
            Roles = userRoles
        };

        //Pass the Model to the View
        return View(model);
    }

    [HttpPost]
    [Authorize(Policy = "EditRolePolicy")]
    public async Task<IActionResult> EditUser(EditUserViewModel model)
    {
        //First Fetch the User by Id from the database
        var user = await _userManager.FindByIdAsync(model.Id);

        //Check if the User Exists in the database
        if (user == null)
        {
            //If the User does not exists in the database, then return Not Found Error View
            ViewBag.ErrorMessage = $"User with Id = {model.Id} cannot be found";
            return View("NotFound");
        }
        else
        {
            //If the User Exists, then proceed and update the data
            //Populate the user instance with the data from EditUserViewModel
            user.Email = model.Email;
            user.UserName = model.UserName;
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;

            //UpdateAsync Method will update the user data in the AspNetUsers Identity table
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                //Once user data updated redirect to the ListUsers view
                return RedirectToAction("ListUsers");
            }
            else
            {
                //In case any error, stay in the same view and show the model validation error
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(model);
        }
    }

    [HttpPost]
    public async Task<IActionResult> DeleteUser(string UserId)
    {
        //First Fetch the User you want to Delete
        var user = await _userManager.FindByIdAsync(UserId);

        if (user == null)
        {
            // Handle the case where the user wasn't found
            ViewBag.ErrorMessage = $"User with Id = {UserId} cannot be found";
            return View("NotFound");
        }
        else
        {
            //Delete the User Using DeleteAsync Method of UserManager Service
            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                // Handle a successful delete
                return RedirectToAction("ListUsers");
            }
            else
            {
                // Handle failure
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View("ListUsers");
        }
    }
}
