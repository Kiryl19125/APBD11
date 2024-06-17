using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JWT.Contexts;
using JWT.Models;
using JWT.RequestModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers;

[Route("api/[controller]")]
[ApiController]
public class Controller : ControllerBase
{
    private readonly IConfiguration config;
    private readonly UserManager<IdentityUser> userManager;
    private readonly DatabaseContext context;

    public Controller(IConfiguration config, UserManager<IdentityUser> userManager, DatabaseContext context)
    {
        this.config = config;
        this.userManager = userManager;
        this.context = context;
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequestModel model)
    {
        if (!await AuthenticateUser(model.UserName, model.Password))
        {
            return Unauthorized("Invalid credentials");
        }

        var (accessToken, refreshToken) = await GenerateTokens(model.UserName);

        await StoreRefreshToken(model.UserName, refreshToken);

        return Ok(new LoginResponseModel
        {
            Token = accessToken,
            RefreshToken = refreshToken
        });
    }

    private async Task<bool> AuthenticateUser(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);
        return user != null && await userManager.CheckPasswordAsync(user, password);
    }

    private async Task<(string accessToken, string refreshToken)> GenerateTokens(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(config["JWT:Key"]);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username)
        };

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            )
        });

        return (tokenHandler.WriteToken(token), GenerateRefreshToken());
    }

    private async Task StoreRefreshToken(string username, string refreshToken)
    {
        context.RefreshTokens.Add(new RefreshModel
        {
            Token = refreshToken,
            UserName = username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        });
        await context.SaveChangesAsync();
    }


    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshTokenRequestModel model)
    {
        var (isValid, username) = await ValidateRefreshToken(model.RefreshToken);
        if (!isValid)
        {
            return Unauthorized("Invalid refresh token");
        }

        var (newAccessToken, newRefreshToken) = await GenerateNewTokens(username);
        await UpdateRefreshToken(model.RefreshToken, newRefreshToken);

        return Ok(new LoginResponseModel
        {
            Token = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    private async Task<(bool isValid, string username)> ValidateRefreshToken(string token)
    {
        var refreshToken = await context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token && rt.ExpiryDate > DateTime.UtcNow);

        if (refreshToken == null)
        {
            return (false, null);
        }

        var user = await userManager.FindByNameAsync(refreshToken.UserName);
        return user != null ? (true, user.UserName) : (false, null);
    }

    private async Task<(string accessToken, string refreshToken)> GenerateNewTokens(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(config["JWT:Key"]);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username)
        };

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            )
        });

        return (tokenHandler.WriteToken(token), GenerateRefreshToken());
    }

    private async Task UpdateRefreshToken(string oldToken, string newToken)
    {
        var refreshToken = await context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == oldToken);

        if (refreshToken != null)
        {
            refreshToken.Token = newToken;
            refreshToken.ExpiryDate = DateTime.UtcNow.AddDays(1);
            context.RefreshTokens.Update(refreshToken);
            await context.SaveChangesAsync();
        }
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequestModel model)
    {
        var user = new IdentityUser { UserName = model.UserName };
        var result = await userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            return Ok("Registered.");
        }

        return BadRequest(result.Errors);
    }

    [HttpGet("get")]
    [Authorize]
    public IActionResult GetSecretData()
    {
        return Ok("Secret data.");
    }


    private string GenerateRefreshToken(int size = 32)
    {
        {
            byte[] randomNumber = new byte[size];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }

            return Convert.ToBase64String(randomNumber);
        }
    }
}