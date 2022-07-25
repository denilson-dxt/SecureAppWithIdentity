using Microsoft.AspNetCore.Mvc;
using  Microsoft.AspNetCore.Authorization;
using SecureAppWithIdentity.Models;
using Microsoft.AspNetCore.Identity;

namespace SecureAppWithIdentity.Controllers;

[ApiController]
[Authorize]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;
    private readonly UserManager<IdentityUser> _userManager;

    public WeatherForecastController(ILogger<WeatherForecastController> logger, UserManager<IdentityUser> userManager)
    {
        _logger = logger;
        _userManager = userManager;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        System.Console.WriteLine(User.Identity.Name);
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
    }
}