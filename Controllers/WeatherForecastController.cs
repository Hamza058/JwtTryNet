using JwtTryNet.Token;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using JwtTryNet.Models;
using System.Security.Cryptography;

namespace JwtTryNet.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public static User user = new User();

    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    [Authorize]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpPost("Created")]
    public IActionResult CreateToken(UserDto request)
    {
        user.Username = request.Username;
        return Created("", new BuildToken(_configuration).CreateToken(user));
    }

    [HttpPost("Login")]
    public IActionResult Login(UserDto request)
    {
        /*var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name,pass)
        };
        var useridentity = new ClaimsIdentity(claims, "a");
        ClaimsPrincipal principal = new ClaimsPrincipal(useridentity);
        await HttpContext.SignInAsync(principal);*/
        if(request.Username == user.Username)
        {
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);
            return Ok();
        }
        else
        {
            return Ok("yanlış kullanıcı adı");
        }
    }

    [HttpPost("refresh-token")]
    public ActionResult<string> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if(!user.RefreshToken.Equals(refreshToken))
        {
            return Unauthorized("Invalid Refresh Token");
        }
        else if(user.TokenExpires < DateTime.Now)
        {
            return Unauthorized("Token expired."); 
        }

        string token = new BuildToken(_configuration).CreateToken(user);
        var newRefreshToken = GenerateRefreshToken();
        SetRefreshToken(newRefreshToken);

        return Ok(token);
    }

    private RefreshToken GenerateRefreshToken()
    {
        var refreshToken = new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.Now.AddDays(7)
        };
        
        return refreshToken;
    }
    private void SetRefreshToken(RefreshToken newRefreshToken)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = newRefreshToken.Expires,
        };
        Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

        user.RefreshToken = newRefreshToken.Token;
        user.TokenCreated = newRefreshToken.Created;
        user.TokenExpires = newRefreshToken.Expires;
    }    
}
