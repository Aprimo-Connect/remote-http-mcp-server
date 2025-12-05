using System.Text;
using System.Text.Json;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace StreamHttpMcp.Services;

// Aprimo DAM API integration service

public class AprimoService
{
    private readonly HttpClient _httpClient;
    private readonly string _baseDamUrl;
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public AprimoService(HttpClient httpClient, string domain, IHttpContextAccessor httpContextAccessor)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _baseDamUrl = $"https://{domain}.dam.aprimo.com";
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
    }
    
    private string? GetBearerTokenFromRequest()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            return null;
        }
        
        if (!httpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            return null;
        }
        
        var authHeaderValue = authHeader.ToString();
        if (string.IsNullOrEmpty(authHeaderValue))
        {
            return null;
        }
        
        if (!authHeaderValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        
        return authHeaderValue.Substring(7).Trim();
    }
    
    public async Task<string> SearchAprimo(string query)
    {
        try
        {
            var bearerToken = GetBearerTokenFromRequest();
            if (string.IsNullOrEmpty(bearerToken))
            {
                throw new InvalidOperationException("No Bearer token found in the Authorization header. The MCP Client must provide a valid access token.");
            }
            
            var endpoint = $"{_baseDamUrl}/api/core/search/records";
            
            var searchRequest = new
            {
                searchExpression = new
                {
                    expression = query
                },
                logRequest = true
            };
            
            var jsonContent = JsonSerializer.Serialize(searchRequest);
            var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
            
            var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = content
            };
            
            request.Headers.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
            
            request.Headers.Add("API-VERSION", "1");
            request.Headers.Add("User-Agent", "StreamHttpMcp");
            request.Headers.Add("select-record", "title, preview, thumbnail");
            request.Headers.Add("pageSize", "15");
            request.Headers.Add("page", "1");
            
            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new InvalidOperationException($"Search request failed: {response.StatusCode} - {errorContent}");
            }
            
            var responseContent = await response.Content.ReadAsStringAsync();
            return responseContent;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to search Aprimo with query '{query}': {ex.Message}", ex);
        }
    }

    public async Task<string> DownloadOrder(string recordId)
    {
        try
        {
            var bearerToken = GetBearerTokenFromRequest();
            if (string.IsNullOrEmpty(bearerToken))
            {
                throw new InvalidOperationException("No Bearer token found in the Authorization header. The MCP Client must provide a valid access token.");
            }
            
            Console.WriteLine($"[APRIMO SERVICE] DownloadOrder called with recordId: {recordId}");
            
            var endpoint = $"{_baseDamUrl}/api/core/orders";
            
            var downloadRequest = new
            {
                type = "download",
                disableNotification = true,
                targets = new[]
                {
                    new
                    {
                        recordId = recordId,
                        targetTypes = new[] { "Document" },
                        assetType = "LatestVersionOfMasterFile"
                    }
                }
            };
            
            var jsonContent = JsonSerializer.Serialize(downloadRequest);
            var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
            
            var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = content
            };
            
            request.Headers.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
            
            request.Headers.Add("API-VERSION", "1");
            request.Headers.Add("User-Agent", "StreamHttpMcp");
            
            var response = await _httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new InvalidOperationException($"Download order request failed: {response.StatusCode} - {errorContent}");
            }
            
            var responseContent = await response.Content.ReadAsStringAsync();
            var orderResponse = JsonSerializer.Deserialize<DownloadOrderResponse>(responseContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            
            if (orderResponse?.DeliveredFiles == null || orderResponse.DeliveredFiles.Length == 0)
            {
                throw new InvalidOperationException("No download URL found in the order response");
            }
            
            var downloadUrl = orderResponse.DeliveredFiles[0];
            Console.WriteLine($"[APRIMO SERVICE] Download order completed successfully. Download URL: {downloadUrl}");
            
            return downloadUrl;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to create download order for recordId '{recordId}': {ex.Message}", ex);
        }
    }
    
    private class DownloadOrderResponse
    {
        public string[]? DeliveredFiles { get; set; }
        public string? Status { get; set; }
        public string? Id { get; set; }
        public string? Type { get; set; }
        public string? Message { get; set; }
    }
}
