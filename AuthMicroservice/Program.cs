using AuthMicroservice.Extensions;
using Serilog;
using Serilog.Events;

// ── Bootstrap logger (used before DI is built) ────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Auth Microservice...");

    var builder = WebApplication.CreateBuilder(args);

    // ── Serilog ───────────────────────────────────────────────────────────────
    builder.Host.UseSerilog((ctx, services, loggerConfig) =>
        loggerConfig
            .ReadFrom.Configuration(ctx.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "AuthMicroservice")
            .Enrich.WithProperty("Environment", ctx.HostingEnvironment.EnvironmentName)
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
            .WriteTo.File("logs/auth-.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    );

    // ── Services ──────────────────────────────────────────────────────────────
    builder.Services.AddDatabase(builder.Configuration);
    builder.Services.AddJwtAuthentication(builder.Configuration);
    builder.Services.AddRateLimiting(builder.Configuration);
    builder.Services.AddSwaggerWithJwt();
    builder.Services.AddApplicationServices();

    builder.Services.AddControllers();
    builder.Services.AddAuthorization();

    builder.Services.AddCors(options =>
    {
        var frontendUrl = builder.Configuration["FrontendUrl"] ?? "http://localhost:3000";
        options.AddDefaultPolicy(policy =>
            policy.WithOrigins(frontendUrl)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials());
    });

    builder.Services.AddHealthChecks();

    // ── App ───────────────────────────────────────────────────────────────────
    var app = builder.Build();

    app.UseSerilogRequestLogging(opts =>
    {
        opts.MessageTemplate =
            "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000}ms";
    });

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth Microservice v1");
            options.RoutePrefix = "swagger";
            options.DisplayRequestDuration();
        });
    }

    app.UseHttpsRedirection();
    app.UseCors();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();
    app.MapHealthChecks("/health");

    // ── Run DB migrations on startup ──────────────────────────────────────────
    await app.Services.MigrateDatabaseAsync();

    await app.RunAsync();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

return 0;
