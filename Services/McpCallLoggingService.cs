using System.Text;
using System.Text.Json;

namespace StreamHttpMcp.Services
{
    /// <summary>
    /// Service for logging MCP tool calls to a dedicated log file
    /// </summary>
    public class McpCallLoggingService
    {
        private readonly string _logFilePath;
        private readonly object _lockObject = new object();
        private readonly ILogger<McpCallLoggingService> _logger;

        public McpCallLoggingService(ILogger<McpCallLoggingService> logger, IConfiguration configuration)
        {
            _logger = logger;
            
            // Get log file path from configuration or use default
            var logDirectory = configuration["Logging:FileLogging:Directory"] ?? "Logs";
            var logFileName = "mcp_calls.log";
            
            // Ensure log directory exists
            if (!Directory.Exists(logDirectory))
            {
                Directory.CreateDirectory(logDirectory);
            }
            
            _logFilePath = Path.Combine(logDirectory, logFileName);
        }

        /// <summary>
        /// Logs an MCP call with the method name and other relevant details
        /// </summary>
        public async Task LogMcpCallAsync(HttpContext context, string requestBody)
        {
            try
            {
                // Parse the JSON body to extract the method
                string? method = null;
                string? id = null;
                
                if (!string.IsNullOrEmpty(requestBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(requestBody);
                        var root = doc.RootElement;
                        
                        if (root.TryGetProperty("method", out var methodElement))
                        {
                            method = methodElement.GetString();
                        }
                        
                        if (root.TryGetProperty("id", out var idElement))
                        {
                            id = idElement.ValueKind == JsonValueKind.String 
                                ? idElement.GetString() 
                                : idElement.GetRawText();
                        }
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse MCP request body as JSON");
                        return; // Don't log if we can't parse it
                    }
                }

                // Only log if we have a method (skip notifications without method or invalid requests)
                if (string.IsNullOrEmpty(method))
                {
                    return;
                }

                var logEntry = new StringBuilder();
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
                
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"MCP CALL LOGGED AT: {timestamp}");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"Method: {method}");
                if (!string.IsNullOrEmpty(id))
                {
                    logEntry.AppendLine($"ID: {id}");
                }
                logEntry.AppendLine($"Path: {context.Request.Path}");
                logEntry.AppendLine($"RemoteIP: {context.Connection.RemoteIpAddress}");
                logEntry.AppendLine($"UserAgent: {context.Request.Headers.UserAgent}");
                logEntry.AppendLine($"");
                logEntry.AppendLine($"REQUEST BODY:");
                logEntry.AppendLine($"-----");
                logEntry.AppendLine(requestBody);
                logEntry.AppendLine($"");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"END MCP CALL");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine("");

                await WriteToFileAsync(logEntry.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging MCP call to file");
            }
        }

        /// <summary>
        /// Writes text to the log file in a thread-safe manner
        /// </summary>
        private async Task WriteToFileAsync(string content)
        {
            await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    File.AppendAllText(_logFilePath, content, Encoding.UTF8);
                }
            });
        }

        /// <summary>
        /// Gets the current log file path
        /// </summary>
        public string GetLogFilePath()
        {
            return _logFilePath;
        }
    }
}

