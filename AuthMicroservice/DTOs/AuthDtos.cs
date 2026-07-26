using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.DTOs;

// ── Requests ──────────────────────────────────────────────────────────────────

public record RegisterRequest(
    [Required, EmailAddress, MaxLength(256)] string Email,
    [Required, MinLength(2), MaxLength(50), RegularExpression(@"^[a-zA-Z0-9_-]+$",
        ErrorMessage = "Username may only contain letters, digits, _ and -")]
    string Username,
    [Required, MinLength(8), MaxLength(128)] string Password,
    [Required] string ConfirmPassword
);

public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password
);

public record RefreshTokenRequest(
    [Required] string RefreshToken
);

public record RevokeTokenRequest(
    [Required] string RefreshToken
);

// ── Responses ─────────────────────────────────────────────────────────────────

public record UserDto(
    Guid Id,
    string Email,
    string Username,
    bool HasPassword,
    bool HasGoogleLinked,
    DateTime CreatedAt
);

public record AuthResponse(
    string AccessToken,
    string RefreshToken,
    int ExpiresIn,
    UserDto User
);

public record ApiError(string Error, string? Detail = null);
