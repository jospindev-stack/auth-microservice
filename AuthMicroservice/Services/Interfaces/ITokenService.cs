using System.Security.Claims;
using AuthMicroservice.Entities;

namespace AuthMicroservice.Services.Interfaces;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    RefreshToken GenerateRefreshToken(string? ipAddress);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    Guid? GetUserIdFromToken(string token);
}
