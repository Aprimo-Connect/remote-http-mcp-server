// MCP OAuth authorization middleware - validates authentication and scopes

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace StreamHttpMcp.Middleware
{
public class McpOAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<McpOAuthMiddleware> _logger;
    private readonly IConfiguration _configuration;

    public McpOAuthMiddleware(
        RequestDelegate next,
        ILogger<McpOAuthMiddleware> logger,
        IConfiguration configuration)
    {
        _next = next;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip authorization for discovery endpoints and redirect endpoints
        if (context.Request.Path.StartsWithSegments("/.well-known") || 
            context.Request.Path.StartsWithSegments("/authorize"))
        {
            await _next(context);
            return;
        }

        if (!context.Request.Path.StartsWithSegments("/mcp"))
        {
            await _next(context);
            return;
        }

        var requiredScopes = GetRequiredScopesForEndpoint(context.Request.Path);
        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var resourceMetadataUrl = $"{baseUrl}/.well-known/oauth-protected-resource";

        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            var wwwAuthenticateValue = $"Bearer resource_metadata=\"{resourceMetadataUrl}\", " +
                                     $"scope=\"{string.Join(" ", requiredScopes)}\"";

            context.Response.StatusCode = 401;
            context.Response.Headers["WWW-Authenticate"] = wwwAuthenticateValue;
            context.Response.ContentType = "application/json";
            
            var errorResponse = new
            {
                error = "invalid_token",
                error_description = "The access token is missing or invalid",
                error_uri = "https://tools.ietf.org/html/rfc6750#section-3.1"
            };

            _logger.LogWarning("Unauthenticated request to MCP endpoint from {RemoteIP}", 
                context.Connection.RemoteIpAddress);
            
            await context.Response.WriteAsJsonAsync(errorResponse);
            return;
        }

        var userScopes = GetUserScopes(context.User);
        var missingScopes = requiredScopes.Except(userScopes).ToList();
        
        if (missingScopes.Any())
        {
            var wwwAuthenticateValue = $"Bearer resource_metadata=\"{resourceMetadataUrl}\", " +
                                     $"scope=\"{string.Join(" ", requiredScopes)}\", " +
                                     $"error=\"insufficient_scope\", " +
                                     $"error_description=\"The request requires higher privileges than provided by the access token\"";

            context.Response.StatusCode = 403;
            context.Response.Headers["WWW-Authenticate"] = wwwAuthenticateValue;
            context.Response.ContentType = "application/json";
            
            var errorResponse = new
            {
                error = "insufficient_scope",
                error_description = $"The request requires the following scopes: {string.Join(", ", missingScopes)}",
                scope = string.Join(" ", requiredScopes),
                error_uri = "https://tools.ietf.org/html/rfc6750#section-3.1"
            };

            _logger.LogWarning("Insufficient scope for request. User has: {UserScopes}, Required: {RequiredScopes}", 
                string.Join(", ", userScopes), 
                string.Join(", ", requiredScopes));
            
            await context.Response.WriteAsJsonAsync(errorResponse);
            return;
        }

        _logger.LogDebug("Request authenticated and authorized. User: {User}, Scopes: {Scopes}", 
            context.User.Identity?.Name ?? "Unknown",
            string.Join(", ", userScopes));
        
        await _next(context);
    }

    private List<string> GetUserScopes(ClaimsPrincipal user)
    {
        var scopes = new List<string>();
        
        var scopeClaim = user.FindFirst("scope")?.Value;
        if (!string.IsNullOrEmpty(scopeClaim))
        {
            scopes.AddRange(scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }
        
        var scpClaim = user.FindFirst("scp")?.Value;
        if (!string.IsNullOrEmpty(scpClaim))
        {
            scopes.AddRange(scpClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }
        
        var allScopeClaims = user.FindAll("scope");
        foreach (var claim in allScopeClaims)
        {
            if (!string.IsNullOrEmpty(claim.Value))
            {
                scopes.AddRange(claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            }
        }
        
        return scopes.Distinct().ToList();
    }

    private List<string> GetRequiredScopesForEndpoint(PathString path)
    {
        var requiredScopesConfig = _configuration.GetSection("OAuth:Scopes:Required").Get<string[]>();
        var requiredScopes = requiredScopesConfig?.ToList() ?? new List<string> { "mcp:access" };
        
        return requiredScopes;
    }
}

public static class McpOAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseMcpOAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<McpOAuthMiddleware>();
    }
}
}

