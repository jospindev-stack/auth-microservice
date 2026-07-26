using AuthMicroservice.Data;
using AuthMicroservice.DTOs;
using AuthMicroservice.Entities;
using AuthMicroservice.Services.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthMicroservice.Services;

public class AuthService(
    AppDbContext db,
    ITokenService tokenService,
    IConfiguration config,
    ILogger<AuthService> logger) : IAuthService
{
    private readonly int _accessExpirySeconds =
        int.Parse(config["JwtSettings:AccessTokenExpiryMinutes"] ?? "15") * 60;

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request, string? ipAddress)
    {
        if (request.Password != request.ConfirmPassword)
            throw new InvalidOperationException("Passwords do not match");

        var email = request.Email.ToLowerInvariant();

        if (await db.Users.AnyAsync(u => u.Email == email))
            throw new InvalidOperationException("Email is already registered");

        if (await db.Users.AnyAsync(u => u.Username == request.Username))
            throw new InvalidOperationException("Username is already taken");

        var user = new User
        {
            Email = email,
            Username = request.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
        };

        var refreshToken = tokenService.GenerateRefreshToken(ipAddress);
        refreshToken.UserId = user.Id;
        user.RefreshTokens.Add(refreshToken);

        db.Users.Add(user);
        await db.SaveChangesAsync();

        logger.LogInformation("User {UserId} registered — email {Email}", user.Id, email);
        return BuildAuthResponse(user, refreshToken);
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request, string? ipAddress)
    {
        var email = request.Email.ToLowerInvariant();

        var user = await db.Users
            .Include(u => u.RefreshTokens)
            .FirstOrDefaultAsync(u => u.Email == email)
            ?? throw new UnauthorizedAccessException("Invalid credentials");

        if (!user.IsActive)
            throw new UnauthorizedAccessException("Account is disabled");

        if (user.PasswordHash is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            throw new UnauthorizedAccessException("Invalid credentials");

        await RevokeExpiredTokensAsync(user, ipAddress);

        var refreshToken = tokenService.GenerateRefreshToken(ipAddress);
        refreshToken.UserId = user.Id;
        user.RefreshTokens.Add(refreshToken);
        await db.SaveChangesAsync();

        logger.LogInformation("User {UserId} logged in from {Ip}", user.Id, ipAddress);
        return BuildAuthResponse(user, refreshToken);
    }

    public async Task<AuthResponse> RefreshTokenAsync(string token, string? ipAddress)
    {
        var existing = await db.RefreshTokens
            .Include(rt => rt.User).ThenInclude(u => u.RefreshTokens)
            .FirstOrDefaultAsync(rt => rt.Token == token)
            ?? throw new UnauthorizedAccessException("Invalid refresh token");

        if (existing.IsRevoked)
        {
            // Token reuse detected — revoke the entire family as a security measure
            logger.LogWarning("Refresh token reuse detected for user {UserId}", existing.UserId);
            await RevokeAllActiveTokensAsync(existing.User, ipAddress);
            await db.SaveChangesAsync();
            throw new UnauthorizedAccessException("Refresh token reuse detected — all sessions invalidated");
        }

        if (existing.IsExpired)
            throw new UnauthorizedAccessException("Refresh token has expired");

        var newToken = tokenService.GenerateRefreshToken(ipAddress);
        newToken.UserId = existing.UserId;

        existing.IsRevoked = true;
        existing.RevokedAt = DateTime.UtcNow;
        existing.RevokedByIp = ipAddress;
        existing.ReplacedByToken = newToken.Token;

        existing.User.RefreshTokens.Add(newToken);
        await db.SaveChangesAsync();

        logger.LogInformation("Refresh token rotated for user {UserId}", existing.UserId);
        return BuildAuthResponse(existing.User, newToken);
    }

    public async Task RevokeTokenAsync(string token, string? ipAddress)
    {
        var existing = await db.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token)
            ?? throw new UnauthorizedAccessException("Invalid refresh token");

        if (!existing.IsActive)
            throw new InvalidOperationException("Token is already revoked or expired");

        existing.IsRevoked = true;
        existing.RevokedAt = DateTime.UtcNow;
        existing.RevokedByIp = ipAddress;
        await db.SaveChangesAsync();

        logger.LogInformation("Refresh token revoked for user {UserId}", existing.UserId);
    }

    public async Task<UserDto> GetCurrentUserAsync(Guid userId)
    {
        var user = await db.Users.FindAsync(userId)
            ?? throw new KeyNotFoundException("User not found");
        return ToDto(user);
    }

    public async Task<AuthResponse> GoogleLoginAsync(
        string email, string googleId, string displayName, string? ipAddress)
    {
        var emailLower = email.ToLowerInvariant();

        var user = await db.Users
            .Include(u => u.RefreshTokens)
            .FirstOrDefaultAsync(u => u.GoogleId == googleId || u.Email == emailLower);

        if (user is null)
        {
            user = new User
            {
                Email = emailLower,
                Username = await MakeUniqueUsernameAsync(displayName),
                GoogleId = googleId,
                GoogleEmail = emailLower,
            };
            db.Users.Add(user);
            logger.LogInformation("New user created via Google OAuth: {Email}", emailLower);
        }
        else
        {
            if (user.GoogleId is null)
            {
                user.GoogleId = googleId;
                user.GoogleEmail = emailLower;
                user.UpdatedAt = DateTime.UtcNow;
            }
        }

        if (!user.IsActive)
            throw new UnauthorizedAccessException("Account is disabled");

        await RevokeExpiredTokensAsync(user, ipAddress);

        var refreshToken = tokenService.GenerateRefreshToken(ipAddress);
        refreshToken.UserId = user.Id;
        user.RefreshTokens.Add(refreshToken);
        await db.SaveChangesAsync();

        logger.LogInformation("User {UserId} authenticated via Google", user.Id);
        return BuildAuthResponse(user, refreshToken);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private AuthResponse BuildAuthResponse(User user, RefreshToken refreshToken) =>
        new(tokenService.GenerateAccessToken(user), refreshToken.Token, _accessExpirySeconds, ToDto(user));

    private static UserDto ToDto(User u) =>
        new(u.Id, u.Email, u.Username, u.PasswordHash is not null, u.GoogleId is not null, u.CreatedAt);

    private async Task RevokeExpiredTokensAsync(User user, string? ipAddress)
    {
        foreach (var t in user.RefreshTokens.Where(t => t.IsExpired && !t.IsRevoked))
        {
            t.IsRevoked = true;
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedByIp = ipAddress;
        }
        await db.SaveChangesAsync();
    }

    private static Task RevokeAllActiveTokensAsync(User user, string? ipAddress)
    {
        foreach (var t in user.RefreshTokens.Where(t => t.IsActive))
        {
            t.IsRevoked = true;
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedByIp = ipAddress;
        }
        return Task.CompletedTask;
    }

    private async Task<string> MakeUniqueUsernameAsync(string displayName)
    {
        var sanitized = new string(
            displayName.Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-').ToArray());

        var candidate = sanitized.Length >= 2 ? sanitized[..Math.Min(sanitized.Length, 45)] : "user";

        if (!await db.Users.AnyAsync(u => u.Username == candidate))
            return candidate;

        for (var i = 2; i < 9999; i++)
        {
            var attempt = $"{candidate}{i}";
            if (!await db.Users.AnyAsync(u => u.Username == attempt))
                return attempt;
        }
        return $"user{Guid.NewGuid():N}"[..20];
    }
}
