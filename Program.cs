// Streamable HTTP MCP Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http.Features;
using System.Text;
using StreamHttpMcp.Services;
using StreamHttpMcp.Middleware;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;


var builder = WebApplication.CreateBuilder(args);

// Configure logging: clear providers in Development, keep defaults in Production for Azure logging
if (builder.Environment.IsDevelopment())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(options =>
    {
        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
        options.UseUtcTimestamp = false;
    });
}
else
{
    builder.Logging.AddConsole(options =>
    {
        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
        options.UseUtcTimestamp = false;
    });
}
builder.Logging.SetMinimumLevel(LogLevel.Debug);

var configuration = builder.Configuration;

// Extract OAuth authority and issuer from configuration
var oauthAuthorityRaw = configuration["OAuth:Authority"] ?? 
    throw new InvalidOperationException("OAuth:Authority configuration is required");

var oauthAuthority = oauthAuthorityRaw
    .Replace("/login/connect/authorize", "")
    .Replace("/authorize", "")
    .Replace("/token", "")
    .TrimEnd('/');

var oauthIssuer = oauthAuthorityRaw;
if (oauthIssuer.Contains("/login/connect/authorize"))
{
    oauthIssuer = oauthIssuer.Replace("/login/connect/authorize", "/login");
}
else if (oauthIssuer.Contains("/connect/authorize"))
{
    oauthIssuer = oauthIssuer.Replace("/connect/authorize", "");
}
else if (oauthIssuer.Contains("/authorize"))
{
    oauthIssuer = oauthIssuer.Replace("/authorize", "");
}
oauthIssuer = oauthIssuer.Replace("/token", "").TrimEnd('/');

// Audience: The identifier for this API/resource server
// This must match the "aud" claim in the JWT token
var oauthAudience = configuration["OAuth:Audience"] ?? 
    throw new InvalidOperationException("OAuth:Audience configuration is required");

// Configure JWT Bearer authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = oauthIssuer;
        options.Audience = oauthAudience;
        options.RequireHttpsMetadata = configuration.GetValue<bool>("OAuth:RequireHttps", false);
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = configuration.GetValue<bool>("OAuth:ValidateIssuer", true),
            ValidIssuer = oauthIssuer,
            ValidateAudience = configuration.GetValue<bool>("OAuth:ValidateAudience", true),
            ValidAudience = "api",
            ValidateLifetime = configuration.GetValue<bool>("OAuth:ValidateLifetime", true),
            ValidateIssuerSigningKey = configuration.GetValue<bool>("OAuth:ValidateIssuerSigningKey", true),
            ClockSkew = TimeSpan.FromMinutes(5)
        };
        
        options.Events = new JwtBearerEvents
        {
            // Called when authentication fails
            // This happens when:
            // - Token is missing
            // - Token is malformed
            // - Token signature is invalid
            // - Token is expired
            // - Token audience/issuer don't match
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogWarning("JWT Authentication failed: {Error}", context.Exception.Message);
                return Task.CompletedTask;
            },
            
            // Called when a token is successfully validated
            // At this point, we know:
            // - The token is valid
            // - The token hasn't expired
            // - The token was issued by the correct authority
            // - The token is for this audience
            // However, we still need to check scopes (done in the middleware)
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var user = context.Principal?.Identity?.Name ?? "Unknown";
                logger.LogInformation("JWT Token validated successfully for user: {User}", user);
                return Task.CompletedTask;
            },
            
            // Called when a challenge is issued (401 response)
            // We set the proper WWW-Authenticate header with resource_metadata per RFC 9728
            // This header will be used by the authorization middleware when it challenges
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                
                logger.LogDebug("JWT Authentication challenge issued - setting WWW-Authenticate header with resource_metadata");
                
                var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
                var resourceMetadataUrl = $"{baseUrl}/.well-known/oauth-protected-resource";
                
                var requiredScopesConfig = config.GetSection("OAuth:Scopes:Required").Get<string[]>();
                var requiredScopes = requiredScopesConfig?.ToList() ?? new List<string> { "api" };
                
                var wwwAuthenticateValue = $"Bearer resource_metadata=\"{resourceMetadataUrl}\", " +
                                         $"scope=\"{string.Join(" ", requiredScopes)}\"";
                
                // Remove any default "WWW-Authenticate" header that was already added by the authentication middleware
                context.Response.Headers.Remove("WWW-Authenticate");
                
                // Set our custom header with resource_metadata
                context.Response.Headers["WWW-Authenticate"] = wwwAuthenticateValue;
                
                return Task.CompletedTask;
            }
        };
    });

// Authorization handled by McpOAuthMiddleware, not fallback policy
builder.Services.AddAuthorization(options =>
{
    // options.FallbackPolicy = options.DefaultPolicy; // Disabled - handled by McpOAuthMiddleware
});

// Configure CORS to allow cross-origin requests
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy
            .AllowAnyOrigin()      // Allow requests from any origin
            .AllowAnyMethod()      // Allow all HTTP methods (GET, POST, OPTIONS, etc.)
            .AllowAnyHeader()      // Allow all headers (Authorization, Content-Type, etc.)
            .WithExposedHeaders("WWW-Authenticate"); // Expose WWW-Authenticate header for OAuth
    });
});

// Add controllers for OAuth metadata endpoints
// To act as a Proxy server we need support for 
    // /.well-known/oauth-protected-resource
    // /.well-known/openid-configuration
    // /.well-known/oauth-authorization-server
builder.Services.AddControllers();

// Configure MCP server with HTTP transport
builder.Services.AddMcpServer()
    .WithHttpTransport()       // HTTP transport for streaming capabilities
    .WithResourcesFromAssembly() // Auto-discover MCP resources
    .WithPromptsFromAssembly() // Auto-discover MCP prompts
    .WithToolsFromAssembly();   // Auto-discover MCP tools

builder.Services.AddScoped<RequestLoggingService>();
builder.Services.AddHttpContextAccessor();

builder.Services.AddHttpClient<AprimoService>((serviceProvider, httpClient) =>
{
    httpClient.Timeout = TimeSpan.FromMinutes(5);
    httpClient.DefaultRequestHeaders.Add("User-Agent", "StreamHttpMcp/1.0");
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
});

// Register AprimoService with configuration from appsettings.json
builder.Services.AddScoped<AprimoService>((serviceProvider) =>
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
    var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
    var httpClient = httpClientFactory.CreateClient(nameof(AprimoService));
    
    var domain = configuration["Aprimo:Domain"] ?? throw new InvalidOperationException("Aprimo:Domain configuration is required");
    
    return new AprimoService(httpClient, domain, httpContextAccessor);
});

var app = builder.Build();

// Disable response buffering for streaming support
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        if (ctx.Response.ContentType?.StartsWith("text/event-stream") == true)
        {
            ctx.Response.Headers["Cache-Control"] = "no-cache";
            ctx.Response.Headers["X-Accel-Buffering"] = "no";
        }
        return Task.CompletedTask;
    });

    ctx.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();

    await next();
});

app.UseRequestLogging();

// Console logging middleware
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    var fullUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}";
    if (!string.IsNullOrEmpty(context.Request.QueryString.Value))
    {
        fullUri += context.Request.QueryString.Value;
    }
    
    context.Request.EnableBuffering();
    
    string requestBody = null;
    if (context.Request.ContentLength > 0)
    {
        try
        {
            context.Request.Body.Position = 0;
            using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true))
            {
                requestBody = await reader.ReadToEndAsync();
            }
            context.Request.Body.Position = 0; // Reset for next middleware
        }
        catch (Exception ex)
        {
            logger.LogWarning("Failed to read request body: {Error}", ex.Message);
        }
    }
    
    // Log comprehensive request info to console
    logger.LogInformation("=== REQUEST ===");
    logger.LogInformation("Method: {Method}", context.Request.Method);
    logger.LogInformation("Full URI: {FullUri}", fullUri);
    logger.LogInformation("Path: {Path}", context.Request.Path);
    logger.LogInformation("Query String: {QueryString}", context.Request.QueryString.HasValue ? context.Request.QueryString.Value : "(none)");
    logger.LogInformation("Remote IP: {RemoteIP}", context.Connection.RemoteIpAddress);
    logger.LogInformation("Content-Type: {ContentType}", context.Request.ContentType ?? "(none)");
    logger.LogInformation("Content-Length: {ContentLength}", context.Request.ContentLength?.ToString() ?? "(none)");
    
    // Log request body if present
    if (!string.IsNullOrEmpty(requestBody))
    {
        // Truncate very long bodies for readability (show first 2000 chars)
        var bodyPreview = requestBody.Length > 2000 
            ? requestBody.Substring(0, 2000) + $"... (truncated, total length: {requestBody.Length} chars)"
            : requestBody;
        logger.LogInformation("Request Body: {RequestBody}", bodyPreview);
    }
    else
    {
        logger.LogInformation("Request Body: (none)");
    }
    
    // Log Authorization header if present (masked for security)
    if (context.Request.Headers.ContainsKey("Authorization"))
    {
        var authHeader = context.Request.Headers["Authorization"].ToString();
        var maskedAuth = authHeader.Length > 20 
            ? authHeader.Substring(0, 20) + "..." 
            : "***";
        logger.LogInformation("Authorization: {AuthHeader}", maskedAuth);
    }
    
    await next();
    
    // Log comprehensive response info to console
    logger.LogInformation("=== RESPONSE ===");
    logger.LogInformation("Status Code: {StatusCode} {StatusText}", 
        context.Response.StatusCode, 
        GetStatusText(context.Response.StatusCode));
    logger.LogInformation("For URI: {FullUri}", fullUri);
    logger.LogInformation("Content-Type: {ContentType}", context.Response.ContentType ?? "(none)");
    logger.LogInformation("Content-Length: {ContentLength}", context.Response.ContentLength?.ToString() ?? "(none)");
    
    if (context.Response.Headers.ContainsKey("WWW-Authenticate"))
    {
        logger.LogInformation("WWW-Authenticate: {WwwAuthenticate}", context.Response.Headers["WWW-Authenticate"].ToString());
    }
    
    logger.LogInformation("================\n");
});

// Helper method to get HTTP status text
static string GetStatusText(int statusCode) => statusCode switch
{
    200 => "OK",
    201 => "Created",
    204 => "No Content",
    400 => "Bad Request",
    401 => "Unauthorized",
    403 => "Forbidden",
    404 => "Not Found",
    500 => "Internal Server Error",
    502 => "Bad Gateway",
    503 => "Service Unavailable",
    _ => "Unknown"
};

// CORS middleware must be before authentication to handle OPTIONS preflight requests
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<McpOAuthMiddleware>();

// MapMcp("/mcp") - Single MCP endpoint as required by Streamable HTTP spec
// This creates the single MCP endpoint that supports both POST and GET
//
// RequireAuthorization() ensures that:
// 1. The request must include a valid OAuth 2.1 access token
// 2. The token must be validated by the JWT Bearer authentication handler
// 3. The user must have the required scopes (checked by McpOAuthMiddleware)
//
// If authentication/authorization fails, the McpOAuthMiddleware will:
// - Return 401 with WWW-Authenticate header if no token or invalid token
// - Return 403 with WWW-Authenticate header if token lacks required scopes
//
// NOTE: We do NOT use .RequireAuthorization() here because we handle authorization
// in McpOAuthMiddleware. If we used .RequireAuthorization(), the authorization
// middleware would challenge before our middleware runs, preventing us from setting
// the proper WWW-Authenticate header with resource_metadata.
app.MapMcp("/mcp");


// The OAuthMetadataController handles the protected resource metadata endpoint
app.MapControllers();


app.Run();
