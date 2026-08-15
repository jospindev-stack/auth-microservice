using AuthMicroservice.Data;
using AuthMicroservice.DTOs;
using AuthMicroservice.Entities;
using AuthMicroservice.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AuthMicroservice.Tests;

public class AuthServiceTests : IDisposable
{
    private readonly AppDbContext _db;
    private readonly AuthService _service;

    public AuthServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _db = new AppDbContext(options);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtSettings:SecretKey"] = "test-secret-key-that-is-long-enough-for-hmac-sha256-signing",
                ["JwtSettings:Issuer"] = "auth-microservice-tests",
                ["JwtSettings:Audience"] = "auth-microservice-tests",
                ["JwtSettings:AccessTokenExpiryMinutes"] = "15",
                ["JwtSettings:RefreshTokenExpiryDays"] = "7"
            })
            .Build();

        var tokenService = new TokenService(configuration);
        _service = new AuthService(
            _db,
            tokenService,
            configuration,
            NullLogger<AuthService>.Instance);
    }

    [Fact]
    public async Task RegisterAsync_WithValidRequest_CreatesUserAndReturnsTokens()
    {
        var request = new RegisterRequest(
            "Test.User@example.com",
            "testuser",
            "Password123!",
            "Password123!");

        var result = await _service.RegisterAsync(request, "127.0.0.1");

        Assert.NotEmpty(result.AccessToken);
        Assert.NotEmpty(result.RefreshToken);
        Assert.Equal("test.user@example.com", result.User.Email);
        Assert.Equal("testuser", result.User.Username);
        Assert.True(result.User.HasPassword);

        var user = await _db.Users.Include(u => u.RefreshTokens).SingleAsync();
        Assert.NotEqual("Password123!", user.PasswordHash);
        Assert.True(BCrypt.Net.BCrypt.Verify("Password123!", user.PasswordHash));
        Assert.Single(user.RefreshTokens);
    }

    [Fact]
    public async Task RegisterAsync_WhenPasswordsDoNotMatch_Throws()
    {
        var request = new RegisterRequest(
            "user@example.com",
            "testuser",
            "Password123!",
            "DifferentPassword123!");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _service.RegisterAsync(request, null));

        Assert.Equal("Passwords do not match", exception.Message);
        Assert.Empty(_db.Users);
    }

    [Fact]
    public async Task RegisterAsync_WhenEmailAlreadyExists_Throws()
    {
        await AddUserAsync("user@example.com", "existinguser", "Password123!");

        var request = new RegisterRequest(
            "USER@example.com",
            "newuser",
            "Password123!",
            "Password123!");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _service.RegisterAsync(request, null));

        Assert.Equal("Email is already registered", exception.Message);
    }

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ReturnsTokens()
    {
        await AddUserAsync("user@example.com", "testuser", "Password123!");

        var result = await _service.LoginAsync(
            new LoginRequest("USER@example.com", "Password123!"),
            "127.0.0.1");

        Assert.NotEmpty(result.AccessToken);
        Assert.NotEmpty(result.RefreshToken);
        Assert.Equal("user@example.com", result.User.Email);
    }

    [Fact]
    public async Task LoginAsync_WithInvalidPassword_ThrowsUnauthorized()
    {
        await AddUserAsync("user@example.com", "testuser", "Password123!");

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _service.LoginAsync(
                new LoginRequest("user@example.com", "WrongPassword"),
                null));

        Assert.Equal("Invalid credentials", exception.Message);
    }

    [Fact]
    public async Task LoginAsync_WhenAccountIsDisabled_ThrowsUnauthorized()
    {
        var user = await AddUserAsync("user@example.com", "testuser", "Password123!");
        user.IsActive = false;
        await _db.SaveChangesAsync();

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _service.LoginAsync(
                new LoginRequest("user@example.com", "Password123!"),
                null));

        Assert.Equal("Account is disabled", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithActiveToken_RotatesToken()
    {
        await AddUserAsync("user@example.com", "testuser", "Password123!");
        var login = await _service.LoginAsync(
            new LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1");

        var result = await _service.RefreshTokenAsync(login.RefreshToken, "127.0.0.2");

        Assert.NotEqual(login.RefreshToken, result.RefreshToken);

        var oldToken = await _db.RefreshTokens.SingleAsync(t => t.Token == login.RefreshToken);
        Assert.True(oldToken.IsRevoked);
        Assert.Equal(result.RefreshToken, oldToken.ReplacedByToken);
        Assert.Equal("127.0.0.2", oldToken.RevokedByIp);
    }

    [Fact]
    public async Task RefreshTokenAsync_WhenRevokedTokenIsReused_RevokesActiveSessions()
    {
        await AddUserAsync("user@example.com", "testuser", "Password123!");
        var login = await _service.LoginAsync(
            new LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1");
        var rotated = await _service.RefreshTokenAsync(login.RefreshToken, "127.0.0.2");

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _service.RefreshTokenAsync(login.RefreshToken, "127.0.0.3"));

        Assert.Contains("reuse detected", exception.Message, StringComparison.OrdinalIgnoreCase);

        var activeReplacement = await _db.RefreshTokens.SingleAsync(t => t.Token == rotated.RefreshToken);
        Assert.True(activeReplacement.IsRevoked);
    }

    [Fact]
    public async Task RevokeTokenAsync_WithActiveToken_RevokesToken()
    {
        await AddUserAsync("user@example.com", "testuser", "Password123!");
        var login = await _service.LoginAsync(
            new LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1");

        await _service.RevokeTokenAsync(login.RefreshToken, "127.0.0.2");

        var token = await _db.RefreshTokens.SingleAsync(t => t.Token == login.RefreshToken);
        Assert.True(token.IsRevoked);
        Assert.NotNull(token.RevokedAt);
        Assert.Equal("127.0.0.2", token.RevokedByIp);
    }

    private async Task<User> AddUserAsync(string email, string username, string password)
    {
        var user = new User
        {
            Email = email.ToLowerInvariant(),
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return user;
    }

    public void Dispose()
    {
        _db.Dispose();
        GC.SuppressFinalize(this);
    }
}
