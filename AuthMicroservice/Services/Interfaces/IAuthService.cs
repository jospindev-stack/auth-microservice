using AuthMicroservice.DTOs;

namespace AuthMicroservice.Services.Interfaces;

public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request, string? ipAddress);
    Task<AuthResponse> LoginAsync(LoginRequest request, string? ipAddress);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken, string? ipAddress);
    Task RevokeTokenAsync(string refreshToken, string? ipAddress);
    Task<UserDto> GetCurrentUserAsync(Guid userId);
    Task<AuthResponse> GoogleLoginAsync(string email, string googleId, string username, string? ipAddress);
}
