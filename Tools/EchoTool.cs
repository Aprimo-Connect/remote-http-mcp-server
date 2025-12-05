using System.ComponentModel;
using System.Threading.Tasks;
using ModelContextProtocol.Server;
using ModelContextProtocol;

namespace StreamHttpMcp.Services;

[McpServerToolType]
public class EchoTool
{
    [McpServerTool]
    [Description("Echoes back the provided message - basic MCP tool for testing.")]
    public string EchoAsync(string message)
    {
        Console.WriteLine($"[ECHO TOOL] EchoAsync called with message: {message}");
        Console.WriteLine($"[ECHO TOOL] Processing echo request...");
        
        var result = $"Echo: {message}";
        Console.WriteLine($"[ECHO TOOL] Returning result: {result}");
        
        return result;
    }

    /*[McpServerTool]
    [Description("Task meant to mimic a long running task with multiple responses")]
    public async Task<string> LongTaskAsync( 
        int steps = 5, 
        IProgress<ProgressNotificationValue>? progress = null,
        CancellationToken ct = default)
    {
       for (var i = 1; i <= steps; i++)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(500, ct);
            progress?.Report(new ProgressNotificationValue
            {
                Progress = (i * 100) / steps,
                Message = $"Step {i}/{steps}"
            });
        }
        return "Long task complete ✅";
    }*/
}
