using System.Text;
using System.Text.Json;

namespace StreamHttpMcp.Services
{
    /// <summary>
    /// Service for logging HTTP requests and responses to a text file
    /// </summary>
    public class RequestLoggingService
    {
        private readonly string _logFilePath;
        private readonly object _lockObject = new object();
        private readonly ILogger<RequestLoggingService> _logger;

        public RequestLoggingService(ILogger<RequestLoggingService> logger, IConfiguration configuration)
        {
            _logger = logger;
            
            // Get log file path from configuration or use default
            var logDirectory = configuration["Logging:FileLogging:Directory"] ?? "Logs";
            var logFileName = configuration["Logging:FileLogging:FileName"] ?? "requests.log";
            
            // Ensure log directory exists
            if (!Directory.Exists(logDirectory))
            {
                Directory.CreateDirectory(logDirectory);
            }
            
            _logFilePath = Path.Combine(logDirectory, logFileName);
        }

        /// <summary>
        /// Logs a complete HTTP request with all details
        /// </summary>
        public async Task LogRequestAsync(HttpContext context, string requestBody)
        {
            try
            {
                var logEntry = new StringBuilder();
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
                
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"REQUEST LOGGED AT: {timestamp}");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"Method: {context.Request.Method}");
                logEntry.AppendLine($"Path: {context.Request.Path}");
                logEntry.AppendLine($"QueryString: {context.Request.QueryString}");
                logEntry.AppendLine($"Scheme: {context.Request.Scheme}");
                logEntry.AppendLine($"Host: {context.Request.Host}");
                logEntry.AppendLine($"RemoteIP: {context.Connection.RemoteIpAddress}");
                logEntry.AppendLine($"UserAgent: {context.Request.Headers.UserAgent}");
                logEntry.AppendLine($"ContentType: {context.Request.ContentType}");
                logEntry.AppendLine($"ContentLength: {context.Request.ContentLength}");
                logEntry.AppendLine($"Protocol: {context.Request.Protocol}");
                logEntry.AppendLine($"IsHttps: {context.Request.IsHttps}");
                logEntry.AppendLine($"");
                logEntry.AppendLine($"HEADERS:");
                logEntry.AppendLine($"--------");
                
                foreach (var header in context.Request.Headers)
                {
                    logEntry.AppendLine($"  {header.Key}: {header.Value}");
                }
                
                logEntry.AppendLine($"");
                logEntry.AppendLine($"BODY:");
                logEntry.AppendLine($"-----");
                logEntry.AppendLine(requestBody);
                logEntry.AppendLine($"");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"END REQUEST");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine("");

                await WriteToFileAsync(logEntry.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging request to file");
            }
        }

        /// <summary>
        /// Logs a complete HTTP response with all details
        /// </summary>
        public async Task LogResponseAsync(HttpContext context, string responseBody, int statusCode)
        {
            try
            {
                var logEntry = new StringBuilder();
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
                
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"RESPONSE LOGGED AT: {timestamp}");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"Status Code: {statusCode}");
                logEntry.AppendLine($"ContentType: {context.Response.ContentType}");
                logEntry.AppendLine($"ContentLength: {context.Response.ContentLength}");
                logEntry.AppendLine($"");
                logEntry.AppendLine($"RESPONSE HEADERS:");
                logEntry.AppendLine($"----------------");
                
                foreach (var header in context.Response.Headers)
                {
                    logEntry.AppendLine($"  {header.Key}: {header.Value}");
                }
                
                logEntry.AppendLine($"");
                logEntry.AppendLine($"RESPONSE BODY:");
                logEntry.AppendLine($"-------------");
                logEntry.AppendLine(responseBody);
                logEntry.AppendLine($"");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine($"END RESPONSE");
                logEntry.AppendLine($"==========================================");
                logEntry.AppendLine("");

                await WriteToFileAsync(logEntry.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging response to file");
            }
        }

        /// <summary>
        /// Logs a simple message to the file
        /// </summary>
        public async Task LogMessageAsync(string message)
        {
            try
            {
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
                var logEntry = $"[{timestamp}] {message}{Environment.NewLine}";
                await WriteToFileAsync(logEntry);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging message to file");
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
