using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthMicroservice.DTOs;
using AuthMicroservice.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthMicroservice.Controllers;

[ApiController]
[Route("api/auth")]
[Produces("application/json")]
public class AuthController(IAuthService authService, ILogger<AuthController> logger) : ControllerBase
{
    private string? ClientIp =>
        HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
        ?? HttpContext.Connection.RemoteIpAddress?.ToString();

    // ── POST /api/auth/register ────────────────────────────────────────────────

    /// <summary>Register a new account</summary>
    [HttpPost("register")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(new ApiError("Validation failed",
                string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        try
        {
            var result = await authService.RegisterAsync(request, ClientIp);
            return StatusCode(StatusCodes.Status201Created, result);
        }
        catch (InvalidOperationException ex)
        {
            var code = ex.Message.Contains("already") ? StatusCodes.Status409Conflict : StatusCodes.Status400BadRequest;
            return StatusCode(code, new ApiError(ex.Message));
        }
    }

    // ── POST /api/auth/login ───────────────────────────────────────────────────

    /// <summary>Login and receive access + refresh tokens</summary>
    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(new ApiError("Validation failed"));

        try
        {
            return Ok(await authService.LoginAsync(request, ClientIp));
        }
        catch (UnauthorizedAccessException ex)
        {
            logger.LogWarning("Failed login attempt for {Email} from {Ip}", request.Email, ClientIp);
            return Unauthorized(new ApiError(ex.Message));
        }
    }

    // ── POST /api/auth/refresh ─────────────────────────────────────────────────

    /// <summary>Rotate refresh token and obtain a new access token</summary>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        try
        {
            return Ok(await authService.RefreshTokenAsync(request.RefreshToken, ClientIp));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new ApiError(ex.Message));
        }
    }

    // ── POST /api/auth/logout ─────────────────────────────────────────────────

    /// <summary>Revoke the given refresh token (logout)</summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Logout([FromBody] RevokeTokenRequest request)
    {
        try
        {
            await authService.RevokeTokenAsync(request.RefreshToken, ClientIp);
            return NoContent();
        }
        catch (UnauthorizedAccessException ex)
        {
            return BadRequest(new ApiError(ex.Message));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new ApiError(ex.Message));
        }
    }

    // ── GET /api/auth/me ──────────────────────────────────────────────────────

    /// <summary>Get the authenticated user's profile</summary>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Me()
    {
        var sub = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                  ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(new ApiError("Invalid token claims"));

        try
        {
            return Ok(await authService.GetCurrentUserAsync(userId));
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new ApiError(ex.Message));
        }
    }
}
