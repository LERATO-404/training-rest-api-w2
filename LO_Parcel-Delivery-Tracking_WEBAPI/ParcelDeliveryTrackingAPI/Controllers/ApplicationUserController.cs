using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ParcelDeliveryTrackingAPI.AuthModels;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ParcelDeliveryTrackingAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApplicationUserController : ControllerBase
    {
        private UserManager<ApplicationUser> _userManager;
        private SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationSettings _appSettings;

        public ApplicationUserController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
            IOptions<ApplicationSettings> appSettings)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _appSettings = appSettings.Value;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<Object> PostApplicationUser(ApplicationUserModel userModel)
        {
            var appUser = new ApplicationUser()
            {
                UserName = userModel.UserName,
                Email = userModel.Email,
                FirstName = userModel.FirstName,
                LastName = userModel.LastName
            };

            if (userModel.Role == null)
            {
                userModel.Role = "Administrator";
            }

            try
            {
                var result = await _userManager.CreateAsync(appUser, userModel.Password);
                if (result.Succeeded)
                {
                    var userResult = await _userManager.AddToRoleAsync(appUser, userModel.Role);
                }
                return Ok(new { username = userModel.UserName, message = $"User {appUser.FirstName} {appUser.LastName} Created Successfully." });

            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "User cannot be created." });
            }
        }


        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {

                var claim = new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim("UserID", user.Id.ToString())
                    };


                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SigningKey));
                string tmpKeyIssuer = _appSettings.JWT_Site_URL;
                int expiryInMinutes = Convert.ToInt32(_appSettings.ExpiryInMinutes);


                var usrToken = new JwtSecurityToken(
                    claims: claim,
                    expires: DateTime.UtcNow.AddMinutes(expiryInMinutes),
                    signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(usrToken),
                    expiration = usrToken.ValidTo,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserName = user.UserName,
                    roles = await _userManager.GetRolesAsync(user)
                });

            }
            else
            {
                return BadRequest(new { message = "Username or password not found." });
            }

        }
    }
}
