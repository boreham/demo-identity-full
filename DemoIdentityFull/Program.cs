using DemoIdentityFull.Data;
using DemoIdentityFull.Models;
using DemoIdentityFull.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<DataContext>(options =>
                        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(
    options =>
    {
        // Password settings
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequiredUniqueChars = 4;
        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("EditRolePolicy", policy => policy.RequireClaim("Edit Role"));
    options.AddPolicy("DeleteRolePolicy", policy => policy.RequireClaim("Delete Role"));
});
// Oauth2 authentication
var GoogleClientId = builder.Configuration["Google:AppId"];
var GoogleClientSecret = builder.Configuration["Google:AppSecret"];
var MicrosoftClientId = builder.Configuration["Microsoft:AppId"];
var MicrosoftClientSecret = builder.Configuration["Microsoft:AppSecret"];
var FacebookClientId = builder.Configuration["Facebook:AppId"];
var FacebookClientSecret = builder.Configuration["Facebook:AppSecret"];

builder.Services.AddAuthentication()
.AddGoogle(options =>
{
    options.ClientId = GoogleClientId;
    options.ClientSecret = GoogleClientSecret;
    // You can set other options as needed.
})
.AddMicrosoftAccount(microsoftOptions =>
{
    microsoftOptions.ClientId = MicrosoftClientId;
    microsoftOptions.ClientSecret = MicrosoftClientSecret;
})
.AddFacebook(facebookOptions =>
{
    facebookOptions.ClientId = FacebookClientId;
    facebookOptions.ClientSecret = FacebookClientSecret;
});

// Configure the Application Cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    // If the LoginPath isn't set, ASP.NET Core defaults the path to /Account/Login.
    options.LoginPath = "/Account/Login"; // Set your login path here

    // If the AccessDenied isn't set, ASP.NET Core defaults the path to /Account/AccessDenied
    options.AccessDeniedPath = "/Account/AccessDenied"; // Set your access denied path
});

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    // Set token lifespan to 2 hours
    options.TokenLifespan = TimeSpan.FromHours(2);
});

builder.Services.AddTransient<ISenderEmail, EmailSender>();
builder.Services.AddTransient<ISMSSender, SMSSender>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
}

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
