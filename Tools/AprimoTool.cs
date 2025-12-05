using System.ComponentModel;
using System.Threading.Tasks;
using ModelContextProtocol.Server;
using ModelContextProtocol;

namespace StreamHttpMcp.Services;

[McpServerToolType]
public class AprimoTool
{
    private readonly AprimoService _aprimoService;

    public AprimoTool(AprimoService aprimoService)
    {
        _aprimoService = aprimoService ?? throw new ArgumentNullException(nameof(aprimoService));
    }

    [McpServerTool]
    [Description("Executes an asset search query to Aprimo's /search/records endpoint with advanced filtering options.")]
    public async Task<string> SearchAprimoAsync(
        string query)
    {
        try
        {
            Console.WriteLine($"[APRIMO TOOL] SearchAprimoAsync called with query: {query}");
            
            // Use the AprimoService to perform the search
            var searchResults = await _aprimoService.SearchAprimo(query);
            
            Console.WriteLine($"[APRIMO TOOL] Search completed successfully. Results length: {searchResults?.Length ?? 0} characters");
            
            return searchResults ?? "No results found";
        }
        catch (Exception ex)
        {
            var errorMessage = $"Error searching Aprimo: {ex.Message}";
            Console.WriteLine($"[APRIMO TOOL] {errorMessage}");
            return errorMessage;
        }
    }

    
    /*[McpServerTool]
    [Description("Takes an Aprimo Record ID and places a download order for the asset")]
    public async Task<string> DownloadAprimoAsync(string recordId)
    {
        try
        {
            Console.WriteLine($"[APRIMO TOOL] DownloadAprimoAsync called with recordId: {recordId}");
            
            // Validate input
            if (string.IsNullOrWhiteSpace(recordId))
            {
                var errorMessage = "Record ID cannot be null or empty";
                Console.WriteLine($"[APRIMO TOOL] {errorMessage}");
                return errorMessage;
            }
            
            // Use the AprimoService to download the order
            var downloadResult = await _aprimoService.DownloadOrder(recordId);
            
            Console.WriteLine($"[APRIMO TOOL] Download order completed successfully for recordId: {recordId}");
            
            return downloadResult ?? "Download order completed but no result returned";
        }
        catch (Exception ex)
        {
            var errorMessage = $"Error downloading Aprimo asset for recordId {recordId}: {ex.Message}";
            Console.WriteLine($"[APRIMO TOOL] {errorMessage}");
            return errorMessage;
        }
    }*/

    /*private string BuildSearchExpression(string query, string? assetType, string? dateStart, string? dateEnd)
    {
        var searchExpression = "";

        // Add query text
        if (!string.IsNullOrWhiteSpace(query))
        {
            searchExpression += $"\"{query.Trim()}\"";
        }

        // Add date range filtering
        if (!string.IsNullOrWhiteSpace(dateStart))
        {
            searchExpression += $" AND CreatedOn >= {dateStart}";
        }
        if (!string.IsNullOrWhiteSpace(dateEnd))
        {
            searchExpression += $" AND CreatedOn <= {dateEnd}";
        }

        // Add asset type filtering
        if (!string.IsNullOrWhiteSpace(assetType) && assetType.ToLower() != "all")
        {
            var contentType = assetType.ToLower() switch
            {
                "image" => "Asset",
                "video" => "Video",
                "document" => "Document",
                "audio" => "Audio",
                _ => assetType
            };
            searchExpression += $" AND ContentType = \"{contentType}\"";
        }

        return searchExpression;
    }*/
}