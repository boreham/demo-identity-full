﻿namespace DemoIdentityFull.Models.ClaimViewModels;

public class RoleClaimsViewModel
{
    public RoleClaimsViewModel()
    {
        //To Avoid runtime exception, we are initializing the Cliams property
        Claims = new List<RoleClaim>();
    }
    public string RoleId { get; set; }
    public List<RoleClaim> Claims { get; set; }
}
