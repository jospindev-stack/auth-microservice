using System.Security.Claims;
using AuthMicroservice.DTOs;
using AuthMicroservice.Services.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;

namespace AuthMicroservice.Controllers;

[ApiController]
[Route("api/oauth")]
[Produces("application/json")]
public class OAuthController(IAuthService authService, IConfiguration config, ILogger<OAuthController> logger)
    : ControllerBase
{
    private string? ClientIp =>
        HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
        ?? HttpContext.Connection.RemoteIpAddress?.ToString();

    // ── GET /api/oauth/google ────────────────────────────────────────────────

    /// <summary>Redirect the user to Google's consent screen</summary>
    [HttpGet("google")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    public IActionResult GoogleLogin([FromQuery] string? returnUrl)
    {
        var callbackUrl = Url.Action(nameof(GoogleCallback), "OAuth",
            new { returnUrl }, Request.Scheme, Request.Host.Value);

        var properties = new AuthenticationProperties
        {
            RedirectUri = callbackUrl,
            Items = { ["returnUrl"] = returnUrl ?? config["FrontendUrl"] ?? "/" },
        };

        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    // ── GET /api/oauth/google/callback ────────────────────────────────────────

    /// <summary>Google OAuth2 callback — issues JWT and redirects to frontend</summary>
    [HttpGet("google/callback")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public async Task<IActionResult> GoogleCallback([FromQuery] string? returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!result.Succeeded)
        {
            logger.LogWarning("Google OAuth callback failed: {Error}", result.Failure?.Message);
            var errorUrl = $"{config["FrontendUrl"]}/auth/error?reason=google_failed";
            return Redirect(errorUrl);
        }

        var email = result.Principal!.FindFirstValue(ClaimTypes.Email);
        var googleId = result.Principal!.FindFirstValue(ClaimTypes.NameIdentifier);
        var name = result.Principal!.FindFirstValue(ClaimTypes.Name) ?? "user";

        if (email is null || googleId is null)
        {
            logger.LogWarning("Missing claims in Google callback — email:{Email} id:{Id}", email, googleId);
            return Redirect($"{config["FrontendUrl"]}/auth/error?reason=missing_claims");
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        try
        {
            var auth = await authService.GoogleLoginAsync(email, googleId, name, ClientIp);
            var frontendUrl = returnUrl ?? config["FrontendUrl"] ?? "/";
            var sep = frontendUrl.Contains('?') ? '&' : '?';
            return Redirect(
                $"{frontendUrl}{sep}accessToken={Uri.EscapeDataString(auth.AccessToken)}" +
                $"&refreshToken={Uri.EscapeDataString(auth.RefreshToken)}" +
                $"&expiresIn={auth.ExpiresIn}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return Redirect($"{config["FrontendUrl"]}/auth/error?reason={Uri.EscapeDataString(ex.Message)}");
        }
    }
}
