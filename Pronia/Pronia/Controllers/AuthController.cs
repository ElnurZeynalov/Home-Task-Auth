using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Pronia.Models;
using Pronia.Utilies;
using Pronia.ViewModel.Authorization;
using System;
using System.Threading.Tasks;

namespace Pronia.Controllers
{
    public class AuthController : Controller
    {
        private UserManager<AppUser> _userManager { get; }

        private SignInManager<AppUser> _signInManager { get; }
        private RoleManager<IdentityRole> _roleManager { get; }
        public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterVM register)
        {
            if (!ModelState.IsValid) return View();
            AppUser user = new AppUser
            {
                FirtsName = register.FirstName,
                LastName = register.LastName,
                Email = register.Email,
                UserName = register.UserName,

            };
            IdentityResult result = await _userManager.CreateAsync(user, register.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("ConfrimPassword", error.Description);
                    return View();
                }
            }
            await _userManager.AddToRoleAsync(user, UserRoles.Member.ToString());
            await _signInManager.SignInAsync(user,true);
            return RedirectToAction("Index", "Home");
        }
        public IActionResult Login()
        {
            return View();
        }
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginVM loginVM)
        {
            AppUser user;
            if (loginVM.UserNameOrEmail.Contains("@"))
            {
                user = await _userManager.FindByEmailAsync(loginVM.UserNameOrEmail);
            }
            else
            {
                user = await _userManager.FindByNameAsync(loginVM.UserNameOrEmail);
            }
            if (user == null)
            {
                ModelState.AddModelError("RememberMe", "login or password is incorrect");
                return View(loginVM);
            }
            var result = await _signInManager.PasswordSignInAsync(user, loginVM.Password, loginVM.RememberMe, true);
            await _signInManager.PasswordSignInAsync(user, loginVM.Password, loginVM.RememberMe, true);
            if (result.IsLockedOut)
            {
                ModelState.AddModelError("RememberMe", "you have used all login attempts. Please try again later");
                return View(loginVM);
            }
            if (!result.Succeeded)
            {
                ModelState.AddModelError("RememberMe", "login or password is incorrect");
                return View(loginVM);
            }
            return RedirectToAction("Index", "Home");
        }
        public async Task CreateRoles()
        {
            foreach (var item in Enum.GetValues(typeof(UserRoles)))
            {
                if(!await _roleManager.RoleExistsAsync(item.ToString()))
                {
                    await _roleManager.CreateAsync(new IdentityRole(item.ToString()));
                }
            }
           
        }
        public async Task<IActionResult> Account()
        {
            AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);
            return View(user);
        }
        [HttpPost]
        public async Task<IActionResult> ChangePassword(string UserName)
        {

        }

    }
}
