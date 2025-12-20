using System.Text;
using StreamHttpMcp.Services;

namespace StreamHttpMcp.Middleware
{
    /// <summary>
    /// Middleware for comprehensive HTTP request and response logging to text file
    /// </summary>
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, RequestLoggingService loggingService, McpCallLoggingService mcpLoggingService)
        {
            // Log the incoming request
            await LogRequestAsync(context, loggingService);

             // Log MCP calls to dedicated log file
            if (context.Request.Path.StartsWithSegments("/mcp"))
            {
                await LogMcpCallAsync(context, mcpLoggingService);
            }
            
            // Capture the response
            await LogResponseAsync(context, loggingService);
        }

        private async Task LogRequestAsync(HttpContext context, RequestLoggingService loggingService)
        {
            try
            {
                // Enable buffering to read the request body
                context.Request.EnableBuffering();
                
                // Read the request body
                string requestBody = string.Empty;
                if (context.Request.ContentLength > 0)
                {
                    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                    requestBody = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0; // Reset position for next middleware
                }

                // Log the complete request
                await loggingService.LogRequestAsync(context, requestBody);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in request logging middleware");
            }
        }

        private async Task LogMcpCallAsync(HttpContext context, McpCallLoggingService mcpLoggingService)
        {
            try
            {
                // Enable buffering to read the request body (if not already done)
                context.Request.EnableBuffering();
                
                // Read the request body
                string requestBody = string.Empty;
                if (context.Request.ContentLength > 0)
                {
                    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                    requestBody = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0; // Reset position for next middleware
                }

                // Log the MCP call
                await mcpLoggingService.LogMcpCallAsync(context, requestBody);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in MCP call logging middleware");
            }
        }


        private async Task LogResponseAsync(HttpContext context, RequestLoggingService loggingService)
        {
            // Store the original response body stream
            var originalBodyStream = context.Response.Body;
            
            try
            {
                // Create a new memory stream to capture the response
                using var responseBodyStream = new MemoryStream();
                context.Response.Body = responseBodyStream;

                // Continue to the next middleware
                await _next(context);

                // Read the response body
                responseBodyStream.Seek(0, SeekOrigin.Begin);
                var responseBody = await new StreamReader(responseBodyStream, Encoding.UTF8).ReadToEndAsync();
                
                // Copy the response back to the original stream
                responseBodyStream.Seek(0, SeekOrigin.Begin);
                await responseBodyStream.CopyToAsync(originalBodyStream);

                // Log the complete response
                await loggingService.LogResponseAsync(context, responseBody, context.Response.StatusCode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in response logging middleware");
                
                // Ensure the response is copied back even if logging fails
                if (context.Response.Body is MemoryStream ms)
                {
                    ms.Seek(0, SeekOrigin.Begin);
                    await ms.CopyToAsync(originalBodyStream);
                }
            }
            finally
            {
                // Restore the original response body stream
                context.Response.Body = originalBodyStream;
            }
        }
    }

    /// <summary>
    /// Extension methods for registering the request logging middleware
    /// </summary>
    public static class RequestLoggingMiddlewareExtensions
    {
        public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<RequestLoggingMiddleware>();
        }
    }
}
