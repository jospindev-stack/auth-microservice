using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthMicroservice.Entities;
using AuthMicroservice.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace AuthMicroservice.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    private readonly string _secretKey = config["JwtSettings:SecretKey"]
        ?? throw new InvalidOperationException("JwtSettings:SecretKey is not configured");
    private readonly string _issuer = config["JwtSettings:Issuer"] ?? "auth-microservice";
    private readonly string _audience = config["JwtSettings:Audience"] ?? "auth-clients";
    private readonly int _accessExpiryMinutes = int.Parse(config["JwtSettings:AccessTokenExpiryMinutes"] ?? "15");
    private readonly int _refreshExpiryDays = int.Parse(config["JwtSettings:RefreshTokenExpiryDays"] ?? "7");

    public string GenerateAccessToken(User user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
        };

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_accessExpiryMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public RefreshToken GenerateRefreshToken(string? ipAddress)
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomBytes),
            ExpiresAt = DateTime.UtcNow.AddDays(_refreshExpiryDays),
            CreatedByIp = ipAddress,
        };
    }

    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)),
            ValidateLifetime = false,  // we intentionally accept expired tokens here
        };

        try
        {
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token, validationParams, out var securityToken);

            if (securityToken is not JwtSecurityToken jwt ||
                !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
                return null;

            return principal;
        }
        catch
        {
            return null;
        }
    }

    public Guid? GetUserIdFromToken(string token)
    {
        var principal = GetPrincipalFromExpiredToken(token);
        var sub = principal?.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(sub, out var id) ? id : null;
    }

    public int AccessTokenExpirySeconds => _accessExpiryMinutes * 60;
}
