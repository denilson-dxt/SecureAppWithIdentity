using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using SecureAppWithIdentity.Models;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using SecureAppWithIdentity.Configuration;
using Microsoft.Extensions.Options;

namespace SecureAppWithIdentity.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController: ControllerBase
{
    private readonly JwtBearerTokenSettings _jwtBearerTokenSettings;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IUserStore<IdentityUser> _userStore;
    private readonly IUserEmailStore<IdentityUser> _emailStore;
    public AuthController(IOptions<JwtBearerTokenSettings> jwtTokenOptions, UserManager<IdentityUser> userManager, IUserStore<IdentityUser> userStore)
    {
        _jwtBearerTokenSettings = jwtTokenOptions.Value;
        _userManager = userManager;
        _userStore = userStore;
        _emailStore = GetEmailStore();

    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody]UserDetails userDetails)
    {
        if(!ModelState.IsValid || userDetails == null)
            return new BadRequestObjectResult(new {Message = "User registration failed"});
        
        var identityUser = new IdentityUser()
        {
            UserName = userDetails.Username,
            Email = userDetails.Email,
        };
        //dentityUser = _userManager.GetUserNameAsync(identityUser)
        await _userStore.SetUserNameAsync(identityUser,identityUser.UserName, CancellationToken.None);
        await _emailStore.SetEmailAsync(identityUser, identityUser.Email, CancellationToken.None);
        var result = await _userManager.CreateAsync(identityUser, userDetails.Password);
        if(!result.Succeeded)
        {
            var dictionary = new ModelStateDictionary();
            foreach(IdentityError error in result.Errors)
            {
                dictionary.AddModelError(error.Code, error.Description);
            }
            return new BadRequestObjectResult(new {Message = "User registration failed", Errors = dictionary});
        }
        return Ok(new {Message  = "User registration successful"});
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login(LoginCredentials credentials)
    {
        IdentityUser identityUser;
        if(!ModelState.IsValid || credentials == null || (identityUser = await ValidateUser(credentials) ) == null)
        {
            return new BadRequestObjectResult(new {Message = "Login failed"});
        }
        var token = GenerateToken(identityUser);
        return Ok(new {Token = token, Message = "Success"});
    }

    [HttpPost]
    [Route("Logout")]
    public async Task<IActionResult> Logout()
    {
        return Ok(new {Token = "token", Message = "Logged out"});
    }

    private async Task<IdentityUser> ValidateUser(LoginCredentials credentials)
    {
        var identityUser = await _userManager.FindByNameAsync(credentials.Username);
        if(identityUser != null)
        {
            var result = _userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, credentials.Password);
            return result == PasswordVerificationResult.Failed ? null: identityUser;
        }
        return null;
    }
    private object GenerateToken(IdentityUser identityUser)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.SecretKey);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, identityUser.UserName.ToString()),
                new Claim(ClaimTypes.Email, identityUser.Email)
            }),
            Expires = DateTime.UtcNow.AddSeconds(_jwtBearerTokenSettings.ExpiryTimeInSeconds),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Audience = _jwtBearerTokenSettings.Audience,
            Issuer = _jwtBearerTokenSettings.Issuer
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
     private IUserEmailStore<IdentityUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<IdentityUser>)_userStore;
        }
}