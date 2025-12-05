// OAuth Protected Resource Metadata Controller (RFC 9728)

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Text;

namespace StreamHttpMcp.Controllers;

[ApiController]
[Route(".well-known")]
[AllowAnonymous]  // Discovery endpoints must be publicly accessible
public class OAuthMetadataController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<OAuthMetadataController> _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public OAuthMetadataController(
        IConfiguration configuration,
        ILogger<OAuthMetadataController> logger,
        IHttpClientFactory httpClientFactory)
    {
        _configuration = configuration;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("oauth-protected-resource")]
    [AllowAnonymous]
    public IActionResult GetProtectedResourceMetadata()
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Protected Resource Metadata requested from {RemoteIP}", 
            timestamp, HttpContext.Connection.RemoteIpAddress);

        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var authorizationServerUrl = _configuration["OAuth:Authority"] ?? 
            throw new InvalidOperationException("OAuth:Authority configuration is required");
        
        var authServerBase = ExtractIssuerFromAuthority(authorizationServerUrl);
        _logger.LogInformation("[{Timestamp}] Authorization server issuer identifier: {AuthServerBase}", timestamp, authServerBase);

        var supportedScopesConfig = _configuration.GetSection("OAuth:Scopes:Supported").Get<string[]>();
        var supportedScopes = supportedScopesConfig ?? new[]
        {
            "api",
            "offline_access"
        };

        var metadata = new
        {
            resource = baseUrl,
            authorization_servers = new[] { baseUrl },
            jwks_uri = $"{authServerBase}/.well-known/openid-configuration/jwks",
            scopes_supported = supportedScopes,
            bearer_methods_supported = new[] { "header" },
            resource_documentation = $"{baseUrl}/docs",
            resource_policy_uri = $"{baseUrl}/policy",
            resource_tos_uri = $"{baseUrl}/terms"
        };
        var returnTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Returning OAuth Protected Resource Metadata:", returnTimestamp);
        _logger.LogInformation("[{Timestamp}]   Resource: {Resource}", returnTimestamp, metadata.resource);
        _logger.LogInformation("[{Timestamp}]   Authorization Servers: {AuthServers}", returnTimestamp, string.Join(", ", metadata.authorization_servers));
        _logger.LogInformation("[{Timestamp}]   Scopes Supported: {Scopes}", returnTimestamp, string.Join(", ", metadata.scopes_supported));
        
        Response.Headers["Cache-Control"] = "public, max-age=3600"; // Cache for 1 hour
        
        return Ok(metadata);
    }

    [HttpGet("oauth-authorization-server")]
    [AllowAnonymous]
    public IActionResult GetOAuthAuthorizationServerMetadata()
    {
        _logger.LogInformation("OAuth Authorization Server Metadata requested from {RemoteIP}", 
            HttpContext.Connection.RemoteIpAddress);

        var authorizationServerUrl = _configuration["OAuth:Authority"] ?? 
            throw new InvalidOperationException("OAuth:Authority configuration is required");
        
        var issuer = $"{Request.Scheme}://{Request.Host}";
        
        var metadata = new
        {
            issuer = issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            registration_endpoint = $"{issuer}/connect/register",  // Fake DCR endpoint
            jwks_uri = $"{issuer}/.well-known/openid-configuration/jwks",

            scopes_supported = new[]
            {
                "openid", "email", "profile", "tenant", "user", "api", "legacy-api",
                "reporting-api", "filestore-access", "brandportal-api", "review-file-service",
                "csp-api", "cip-api", "introspection", "offline_access"
            },
            response_types_supported = new[] { "code", "token", "id_token", "id_token token", "code id_token", "code token", "code id_token token" },
            response_modes_supported = new[] { "form_post", "query", "fragment" },
            grant_types_supported = new[]
            {
                "authorization_code", "client_credentials", "refresh_token", "implicit",
                "password", "urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba"
            },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "private_key_jwt" },
            token_endpoint_auth_signing_alg_values_supported = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" },
            revocation_endpoint = $"{issuer}/connect/revocation",
            revocation_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "private_key_jwt" },
            revocation_endpoint_auth_signing_alg_values_supported = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" },
            introspection_endpoint = $"{issuer}/connect/introspect",
            introspection_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "private_key_jwt" },
            introspection_endpoint_auth_signing_alg_values_supported = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" },
            code_challenge_methods_supported = new[] { "plain", "S256" },
            device_authorization_endpoint = $"{issuer}/connect/deviceauthorization",
            pushed_authorization_request_endpoint = $"{issuer}/connect/par",
            require_pushed_authorization_requests = false,
            backchannel_authentication_endpoint = $"{issuer}/connect/ciba",
            backchannel_token_delivery_modes_supported = new[] { "poll" },
            backchannel_user_code_parameter_supported = true,
            dpop_signing_alg_values_supported = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" }
        };
        
        var returnTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Returning OAuth Authorization Server Metadata:", returnTimestamp);
        _logger.LogInformation("[{Timestamp}]   Issuer: {Issuer}", returnTimestamp, metadata.issuer);
        _logger.LogInformation("[{Timestamp}]   Authorization Endpoint: {AuthEndpoint}", returnTimestamp, metadata.authorization_endpoint);
        _logger.LogInformation("[{Timestamp}]   Token Endpoint: {TokenEndpoint}", returnTimestamp, metadata.token_endpoint);
        
        Response.Headers["Cache-Control"] = "public, max-age=3600"; // Cache for 1 hour
        
        return Ok(metadata);
    }

    private string ExtractIssuerFromAuthority(string authorityUrl)
    {
        var issuer = authorityUrl;
        
        if (issuer.Contains("/login/connect/authorize"))
        {
            issuer = issuer.Replace("/login/connect/authorize", "/login");
        }
        else if (issuer.Contains("/connect/authorize"))
        {
            issuer = issuer.Replace("/connect/authorize", "");
        }
        else if (issuer.Contains("/authorize"))
        {
            issuer = issuer.Replace("/authorize", "");
        }
        
        issuer = issuer.Replace("/token", "").TrimEnd('/');
        
        if (!Uri.IsWellFormedUriString(issuer, UriKind.Absolute))
        {
            _logger.LogError("Issuer identifier is not an absolute URL: {Issuer}", issuer);
            throw new InvalidOperationException($"Issuer identifier must be an absolute URL. Current value: {issuer}");
        }
        
        return issuer;
    }

    [HttpGet("openid-configuration")]
    [AllowAnonymous]
    public IActionResult GetOpenIdConfiguration()
    {
        _logger.LogInformation("OpenID Connect Configuration requested from {RemoteIP}", 
            HttpContext.Connection.RemoteIpAddress);

        var authorizationServerUrl = _configuration["OAuth:Authority"] ?? 
            throw new InvalidOperationException("OAuth:Authority configuration is required");
        
        var issuer = $"{Request.Scheme}://{Request.Host}";
        
        var metadata = new
        {
            issuer = issuer,
            jwks_uri = $"{issuer}/.well-known/openid-configuration/jwks",
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            registration_endpoint = $"{issuer}/connect/register",
            userinfo_endpoint = $"{issuer}/connect/userinfo",
            end_session_endpoint = $"{issuer}/connect/endsession",
            check_session_iframe = $"{issuer}/connect/checksession",
            revocation_endpoint = $"{issuer}/connect/revocation",
            introspection_endpoint = $"{issuer}/connect/introspect",
            device_authorization_endpoint = $"{issuer}/connect/deviceauthorization",
            backchannel_authentication_endpoint = $"{issuer}/connect/ciba",
            pushed_authorization_request_endpoint = $"{issuer}/connect/par",
            require_pushed_authorization_requests = false,
            frontchannel_logout_supported = true,
            frontchannel_logout_session_supported = true,
            backchannel_logout_supported = true,
            backchannel_logout_session_supported = true,
            scopes_supported = new[]
            {
                "openid",
                "email",
                "profile",
                "tenant",
                "user",
                "api",
                "legacy-api",
                "reporting-api",
                "filestore-access",
                "brandportal-api",
                "review-file-service",
                "csp-api",
                "cip-api",
                "introspection",
                "offline_access"
            },
            claims_supported = new[]
            {
                "sub",
                "email",
                "email_verified",
                "name",
                "family_name",
                "given_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
                "host",
                "DSN",
                "CID",
                "DB",
                "DomainId",
                "dam-tenant",
                "username",
                "UID",
                "TID",
                "LID",
                "UT",
                "dam-uid",
                "dam-login",
                "GM",
                "UserRights",
                "Locale"
            },
            grant_types_supported = new[]
            {
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "implicit",
                "password",
                "urn:ietf:params:oauth:grant-type:device_code",
                "urn:openid:params:grant-type:ciba"
            },
            response_types_supported = new[]
            {
                "code",
                "token",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token"
            },
            response_modes_supported = new[]
            {
                "form_post",
                "query",
                "fragment"
            },
            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            },
            token_endpoint_auth_signing_alg_values_supported = new[]
            {
                "RS256",
                "RS384",
                "RS512",
                "PS256",
                "PS384",
                "PS512",
                "ES256",
                "ES384",
                "ES512"
            },
            id_token_signing_alg_values_supported = new[]
            {
                "RS256"
            },
            subject_types_supported = new[]
            {
                "public"
            },
            code_challenge_methods_supported = new[]
            {
                "plain",
                "S256"
            },
            request_parameter_supported = true,
            request_object_signing_alg_values_supported = new[]
            {
                "RS256",
                "RS384",
                "RS512",
                "PS256",
                "PS384",
                "PS512",
                "ES256",
                "ES384",
                "ES512"
            },
            prompt_values_supported = new[]
            {
                "none",
                "login",
                "consent",
                "select_account"
            },
            authorization_response_iss_parameter_supported = true,
            backchannel_token_delivery_modes_supported = new[]
            {
                "poll"
            },
            backchannel_user_code_parameter_supported = true,
            dpop_signing_alg_values_supported = new[]
            {
                "RS256",
                "RS384",
                "RS512",
                "PS256",
                "PS384",
                "PS512",
                "ES256",
                "ES384",
                "ES512"
            }
        };

        var returnTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Returning OpenID Connect Configuration:", returnTimestamp);
        _logger.LogInformation("[{Timestamp}]   Issuer: {Issuer}", returnTimestamp, metadata.issuer);
        _logger.LogInformation("[{Timestamp}]   Authorization Endpoint: {AuthEndpoint}", returnTimestamp, metadata.authorization_endpoint);
        _logger.LogInformation("[{Timestamp}]   Token Endpoint: {TokenEndpoint}", returnTimestamp, metadata.token_endpoint);
        
        Response.Headers["Cache-Control"] = "public, max-age=3600"; // Cache for 1 hour
        
        return Ok(metadata);
    }

    [HttpGet("/connect/authorize")]
    [HttpGet("/authorize")]
    [AllowAnonymous]
    public IActionResult ProxyAuthorizeEndpoint()
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var requestPath = Request.Path.Value ?? "";
        _logger.LogInformation("[{Timestamp}] Authorization proxy request received from {RemoteIP} (via {Path})", 
            timestamp, HttpContext.Connection.RemoteIpAddress, requestPath);

        _logger.LogInformation("[{Timestamp}] === INCOMING AUTHORIZATION REQUEST PARAMETERS ===", timestamp);
        foreach (var param in Request.Query)
        {
            _logger.LogInformation("[{Timestamp}]   {Key} = {Value}", timestamp, param.Key, param.Value.ToString());
        }
        _logger.LogInformation("[{Timestamp}] === END PARAMETERS ===", timestamp);

        var queryParams = new List<string>();
        var allowedScopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "api", "offline_access" };
        
        foreach (var param in Request.Query)
        {
            if (param.Key.Equals("resource", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("[{Timestamp}] Removing 'resource' parameter from forwarded request", timestamp);
                continue;
            }

            if (param.Key.Equals("scope", StringComparison.OrdinalIgnoreCase))
            {
                var originalScopes = param.Value.ToString();
                var scopeList = originalScopes.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var filteredScopes = scopeList.Where(s => allowedScopes.Contains(s)).ToHashSet(StringComparer.OrdinalIgnoreCase);
                filteredScopes.Add("api");
                
                var filteredScopeValue = string.Join(" ", filteredScopes);
                queryParams.Add($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(filteredScopeValue)}");
                _logger.LogInformation("[{Timestamp}] Filtered scope parameter: '{OriginalScopes}' -> '{FilteredScopes}'", 
                    timestamp, originalScopes, filteredScopeValue);
                continue;
            }

            foreach (var value in param.Value)
            {
                queryParams.Add($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(value)}");
            }
        }

        var aprimoDomain = _configuration["Aprimo:Domain"] ?? 
            throw new InvalidOperationException("Aprimo:Domain configuration is required");
        var targetUrl = $"https://{aprimoDomain}.aprimo.com/login/connect/authorize";
        if (queryParams.Count > 0)
        {
            var queryString = "?" + string.Join("&", queryParams);
            targetUrl += queryString;
        }

        _logger.LogInformation("[{Timestamp}] Forwarding authorization request to: {TargetUrl}", timestamp, targetUrl);
        _logger.LogInformation("[{Timestamp}] Query parameters forwarded: {ParamCount} parameters", timestamp, queryParams.Count);

        return Redirect(targetUrl);
    }

    [HttpPost("/token")]
    [HttpPost("/connect/token")]
    [AllowAnonymous]
    public async Task<IActionResult> ProxyTokenEndpoint()
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Token proxy request received from {RemoteIP}", 
            timestamp, HttpContext.Connection.RemoteIpAddress);

        _logger.LogInformation("[{Timestamp}] === INCOMING TOKEN REQUEST PARAMETERS ===", timestamp);
        
        if (Request.Query.Count > 0)
        {
            _logger.LogInformation("[{Timestamp}] Query Parameters:", timestamp);
            foreach (var param in Request.Query)
            {
                _logger.LogInformation("[{Timestamp}]   {Key} = {Value}", timestamp, param.Key, param.Value.ToString());
            }
        }

        var formData = new Dictionary<string, string>();
        if (Request.HasFormContentType && Request.Form != null)
        {
            _logger.LogInformation("[{Timestamp}] Form Data:", timestamp);
            foreach (var param in Request.Form)
            {
                var value = param.Value.ToString();
                formData[param.Key] = value;
                _logger.LogInformation("[{Timestamp}]   {Key} = {Value}", timestamp, param.Key, value);
            }
        }
        
        _logger.LogInformation("[{Timestamp}] === END PARAMETERS ===", timestamp);
        var claudeClientId = _configuration["OAuth:ClaudeClientID"];
        var claudeClientSecret = _configuration["OAuth:ClaudeClientSecret"];
        var vsCodeClientId = _configuration["OAuth:VSCodeClientID"];
        var vsCodeClientSecret = _configuration["OAuth:VSCodeClientSecret"];
        string? clientSecretToInject = null;
        string? detectedClientName = null;
        
        if (formData.TryGetValue("client_id", out var clientId))
        {
            if (!string.IsNullOrEmpty(claudeClientId) && clientId.Equals(claudeClientId, StringComparison.OrdinalIgnoreCase))
            {
                clientSecretToInject = claudeClientSecret;
                detectedClientName = "Claude";
                _logger.LogInformation("[{Timestamp}] Detected Claude client (client_id: {ClientId}), will inject client_secret", timestamp, clientId);
            }
            else if (!string.IsNullOrEmpty(vsCodeClientId) && clientId.Equals(vsCodeClientId, StringComparison.OrdinalIgnoreCase))
            {
                clientSecretToInject = vsCodeClientSecret;
                detectedClientName = "Visual Studio Code";
                _logger.LogInformation("[{Timestamp}] Detected Visual Studio Code client (client_id: {ClientId}), will inject client_secret", timestamp, clientId);
            }
        }
        
        var filteredFormData = new Dictionary<string, string>();
        foreach (var param in formData)
        {
            if (param.Key.Equals("resource", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("[{Timestamp}] Removing 'resource' parameter from forwarded request", timestamp);
                continue;
            }

            filteredFormData[param.Key] = param.Value;
        }
        
        if (!string.IsNullOrEmpty(clientSecretToInject) && !string.IsNullOrEmpty(detectedClientName))
        {
            if (!filteredFormData.ContainsKey("client_secret"))
            {
                filteredFormData["client_secret"] = clientSecretToInject;
                _logger.LogInformation("[{Timestamp}] Injected client_secret for {ClientName} client", timestamp, detectedClientName);
            }
            else
            {
                _logger.LogInformation("[{Timestamp}] client_secret already present in request, not injecting", timestamp);
            }
        }

        var filteredQueryParams = new List<string>();
        foreach (var param in Request.Query)
        {
            if (param.Key.Equals("resource", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("[{Timestamp}] Removing 'resource' query parameter from forwarded request", timestamp);
                continue;
            }

            foreach (var value in param.Value)
            {
                filteredQueryParams.Add($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(value)}");
            }
        }

        var aprimoDomain = _configuration["Aprimo:Domain"] ?? 
            throw new InvalidOperationException("Aprimo:Domain configuration is required");
        var targetUrl = $"https://{aprimoDomain}.aprimo.com/login/connect/token";
        if (filteredQueryParams.Count > 0)
        {
            var queryString = "?" + string.Join("&", filteredQueryParams);
            targetUrl += queryString;
        }

        _logger.LogInformation("[{Timestamp}] Forwarding token request to: {TargetUrl}", timestamp, targetUrl);
        _logger.LogInformation("[{Timestamp}] Form parameters forwarded: {ParamCount} parameters", timestamp, filteredFormData.Count);
        _logger.LogInformation("[{Timestamp}] Query parameters forwarded: {ParamCount} parameters", timestamp, filteredQueryParams.Count);

        try
        {
            var httpClient = _httpClientFactory.CreateClient();
            
            if (Request.Headers.ContainsKey("Authorization"))
            {
                var authHeader = Request.Headers["Authorization"].ToString();
                httpClient.DefaultRequestHeaders.Add("Authorization", authHeader);
                _logger.LogInformation("[{Timestamp}] Forwarding Authorization header (masked for security)", timestamp);
            }
            
            var formContent = new FormUrlEncodedContent(filteredFormData);
            _logger.LogInformation("[{Timestamp}] Content-Type: application/x-www-form-urlencoded", timestamp);

            var response = await httpClient.PostAsync(targetUrl, formContent);
            var responseContent = await response.Content.ReadAsStringAsync();
            
            _logger.LogInformation("[{Timestamp}] Token endpoint response status: {StatusCode}", timestamp, response.StatusCode);
            _logger.LogInformation("[{Timestamp}] Token endpoint response: {Response}", timestamp,
                responseContent.Length > 500 ? responseContent.Substring(0, 500) + "..." : responseContent);

            Response.StatusCode = (int)response.StatusCode;
            
            var headersToSkip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Transfer-Encoding", "Content-Length", "Connection"
            };
            
            foreach (var header in response.Headers)
            {
                if (!headersToSkip.Contains(header.Key))
                {
                    try
                    {
                        Response.Headers[header.Key] = header.Value.ToArray();
                    }
                    catch (InvalidOperationException)
                    {
                        _logger.LogWarning("Could not set response header: {Header}", header.Key);
                    }
                }
            }
            
            foreach (var header in response.Content.Headers)
            {
                if (!headersToSkip.Contains(header.Key))
                {
                    try
                    {
                        Response.Headers[header.Key] = header.Value.ToArray();
                    }
                    catch (InvalidOperationException)
                    {
                        _logger.LogWarning("Could not set response header: {Header}", header.Key);
                    }
                }
            }

            var contentType = response.Content.Headers.ContentType?.MediaType ?? "application/json";
            return Content(responseContent, contentType);
        }
        catch (Exception ex)
        {
            var errorTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _logger.LogError(ex, "[{Timestamp}] Error proxying token request to authorization server", errorTimestamp);
            return StatusCode(500, new { error = "internal_server_error", error_description = "Failed to proxy request to authorization server" });
        }
    }

    [HttpPost("/connect/register")]
    [AllowAnonymous]
    public async Task<IActionResult> RegisterClient()
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        _logger.LogInformation("[{Timestamp}] Dynamic Client Registration request received from {RemoteIP}", 
            timestamp, HttpContext.Connection.RemoteIpAddress);

        if (Request.ContentType == null || !Request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("[{Timestamp}] Invalid content type for DCR request. Expected application/json, got: {ContentType}", 
                timestamp, Request.ContentType ?? "(none)");
            return BadRequest(new { error = "invalid_request", error_description = "Content-Type must be application/json" });
        }

        string requestBody;
        using (var reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            requestBody = await reader.ReadToEndAsync();
        }

        _logger.LogInformation("[{Timestamp}] === INCOMING DCR REQUEST ===", timestamp);
        _logger.LogInformation("[{Timestamp}] Request Body: {RequestBody}", timestamp, requestBody);

        System.Text.Json.JsonElement registrationRequest;
        try
        {
            registrationRequest = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(requestBody);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Timestamp}] Failed to parse DCR request JSON", timestamp);
            return BadRequest(new { error = "invalid_request", error_description = "Invalid JSON in request body" });
        }

        if (registrationRequest.TryGetProperty("redirect_uris", out var redirectUris))
        {
            _logger.LogInformation("[{Timestamp}]   redirect_uris: {RedirectUris}", timestamp, redirectUris);
        }
        if (registrationRequest.TryGetProperty("token_endpoint_auth_method", out var authMethod))
        {
            _logger.LogInformation("[{Timestamp}]   token_endpoint_auth_method: {AuthMethod}", timestamp, authMethod);
        }
        if (registrationRequest.TryGetProperty("grant_types", out var grantTypes))
        {
            _logger.LogInformation("[{Timestamp}]   grant_types: {GrantTypes}", timestamp, grantTypes);
        }
        if (registrationRequest.TryGetProperty("response_types", out var responseTypes))
        {
            _logger.LogInformation("[{Timestamp}]   response_types: {ResponseTypes}", timestamp, responseTypes);
        }
        if (registrationRequest.TryGetProperty("client_name", out var clientNameProp))
        {
            _logger.LogInformation("[{Timestamp}]   client_name: {ClientName}", timestamp, clientNameProp);
        }
        if (registrationRequest.TryGetProperty("scope", out var scope))
        {
            _logger.LogInformation("[{Timestamp}]   scope: {Scope}", timestamp, scope);
        }

        _logger.LogInformation("[{Timestamp}] === END DCR REQUEST ===", timestamp);

        string? clientId = null;
        string? clientSecret = null;
        
        string? clientName = null;
        if (registrationRequest.TryGetProperty("client_name", out var clientNameJson))
        {
            clientName = clientNameJson.GetString();
        }
        
        if (!string.IsNullOrEmpty(clientName))
        {
            if (string.Equals(clientName, "Claude", StringComparison.OrdinalIgnoreCase))
            {
                clientId = _configuration["OAuth:ClaudeClientID"];
                clientSecret = _configuration["OAuth:ClaudeClientSecret"];
                _logger.LogInformation("[{Timestamp}] Detected client_name 'Claude', using ClaudeClientID: {ClientId}", timestamp, clientId);
            }
            else if (string.Equals(clientName, "Visual Studio Code", StringComparison.OrdinalIgnoreCase))
            {
                clientId = _configuration["OAuth:VSCodeClientID"];
                clientSecret = _configuration["OAuth:VSCodeClientSecret"];
                _logger.LogInformation("[{Timestamp}] Detected client_name 'Visual Studio Code', using VSCodeClientID: {ClientId}", timestamp, clientId);
            }
            else
            {
                _logger.LogWarning("[{Timestamp}] Unknown client_name '{ClientName}', defaulting to ClaudeClientID", timestamp, clientName);
            }
        }
        
        if (string.IsNullOrEmpty(clientId))
        {
            clientId = _configuration["OAuth:ClaudeClientID"] ?? 
                throw new InvalidOperationException("OAuth:ClaudeClientID configuration is required. This must be a preconfigured client ID in your authorization server.");
            clientSecret = _configuration["OAuth:ClaudeClientSecret"];
            _logger.LogInformation("[{Timestamp}] No client_name provided or unrecognized, defaulting to ClaudeClientID: {ClientId}", timestamp, clientId);
        }

        _logger.LogInformation("[{Timestamp}] Returning preconfigured client_id: {ClientId}", timestamp, clientId);
        
        var clientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        var requiresSecret = false;
        if (registrationRequest.TryGetProperty("token_endpoint_auth_method", out var authMethodCheck))
        {
            var authMethodValue = authMethodCheck.GetString();
            requiresSecret = !string.IsNullOrEmpty(authMethodValue) && 
                            !authMethodValue.Equals("none", StringComparison.OrdinalIgnoreCase);
        }
        
        var response = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["client_id_issued_at"] = clientIdIssuedAt
        };
        
        if (requiresSecret)
        {
            response["client_secret"] = null;
            response["client_secret_expires_at"] = 0;
        }

        if (registrationRequest.TryGetProperty("redirect_uris", out var redirectUrisProp))
        {
            response["redirect_uris"] = System.Text.Json.JsonSerializer.Deserialize<object[]>(redirectUrisProp.GetRawText()) ?? Array.Empty<object>();
        }
        
        if (registrationRequest.TryGetProperty("token_endpoint_auth_method", out var authMethodProp))
        {
            response["token_endpoint_auth_method"] = authMethodProp.GetString() ?? "none";
        }
        
        if (registrationRequest.TryGetProperty("grant_types", out var grantTypesProp))
        {
            response["grant_types"] = System.Text.Json.JsonSerializer.Deserialize<object[]>(grantTypesProp.GetRawText()) ?? Array.Empty<object>();
        }
        
        if (registrationRequest.TryGetProperty("response_types", out var responseTypesProp))
        {
            response["response_types"] = System.Text.Json.JsonSerializer.Deserialize<object[]>(responseTypesProp.GetRawText()) ?? Array.Empty<object>();
        }
        
        if (registrationRequest.TryGetProperty("client_name", out var clientNameEcho))
        {
            response["client_name"] = clientNameEcho.GetString() ?? string.Empty;
        }
        
        if (registrationRequest.TryGetProperty("client_uri", out var clientUriProp))
        {
            response["client_uri"] = clientUriProp.GetString() ?? string.Empty;
        }
        
        if (registrationRequest.TryGetProperty("scope", out var scopeProp))
        {
            response["scope"] = scopeProp.GetString() ?? string.Empty;
        }
        
        if (registrationRequest.TryGetProperty("software_id", out var softwareIdProp))
        {
            response["software_id"] = softwareIdProp.GetString() ?? string.Empty;
        }
        
        if (registrationRequest.TryGetProperty("software_version", out var softwareVersionProp))
        {
            response["software_version"] = softwareVersionProp.GetString() ?? string.Empty;
        }
        
        _logger.LogInformation("[{Timestamp}] Returning DCR response with client_id: {ClientId}", timestamp, clientId);
        
        Response.Headers["Cache-Control"] = "no-store";
        Response.StatusCode = 201;
        
        return new JsonResult(response)
        {
            StatusCode = 201,
            ContentType = "application/json"
        };
    }

}

