using JwtTryNet.Token;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
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

    [HttpPost("Register")]
    public IActionResult CreateToken(UserDto request)
    {
        request.Password = BCrypt.Net.BCrypt.HashPassword(request.Password);
        user.Username = request.Username;
        user.PasswordHash = request.Password;
        return Ok(request);
    }

    [HttpPost("Login")]
    public IActionResult Login(UserDto request)
    {
        if(request.Username == user.Username && BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            var token = Created("", new BuildToken(_configuration).CreateToken(user));
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);
            Dictionary<string, object> tokens = new Dictionary<string, object>()
            {
                {"authenticate token", token.Value ?? token},
                {"refresh token", refreshToken.Token}
            };
            return Ok(tokens);
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
