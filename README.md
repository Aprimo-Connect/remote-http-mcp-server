# Remote HTTP MCP Server

An OAuth 2.1 proxy server that enables AI assistants (such as Claude Desktop) to securely access protected resources through the Model Context Protocol (MCP). This server acts as an intelligent intermediary between AI clients and enterprise authorization systems, providing compatibility, security, and compliance with industry standards.

## Aprimo's Open Source Policy 
This code is provided by Aprimo _as-is_ as an example of how you might solve a specific business problem. It is not intended for direct use in Production without modification.

You are welcome to submit issues or feedback to help us improve visibility into potential bugs or enhancements. Aprimo may, at its discretion, address minor bugs, but does not guarantee fixes or ongoing support.

It is expected that developers who clone or use this code take full responsibility for supporting, maintaining, and securing any deployments derived from it.

If you are interested in a production-ready and supported version of this solution, please contact your Aprimo account representative. They can connect you with our technical services team or a partner who may be able to build and support a packaged implementation for you.

Please note: This code may include references to non-Aprimo services or APIs. You are responsible for acquiring any required credentials or API keys to use those services—Aprimo does not provide them.

## Overview

This project serves as both an **OAuth proxy server** and a **protected MCP resource server**. It enables modern AI assistants to authenticate and access enterprise APIs through the Model Context Protocol, bridging compatibility gaps between AI clients and authorization systems.

### Key Features

- **OAuth 2.1 Proxy**: Transparently proxies authentication requests to enterprise authorization servers
- **MCP Server**: Provides Model Context Protocol endpoints for AI assistants
- **Dynamic Client Registration**: Emulates DCR for clients that require it
- **Request Transformation**: Filters and normalizes OAuth parameters for compatibility
- **Standards Compliant**: Implements RFC 8414, RFC 9728, RFC 7591, and MCP Authorization specifications

## Use Case

This server enables AI assistants (like Claude Desktop) to:
- Securely authenticate with enterprise authorization systems (e.g., Aprimo)
- Access protected APIs through the Model Context Protocol
- Work with authorization servers that don't support modern OAuth features like Dynamic Client Registration
- Bridge compatibility gaps between modern AI clients and legacy systems

## Configuration

All configuration is done through `appsettings.json`. The following settings are required:

### OAuth Configuration

```json
{
  "OAuth": {
    "ClaudeClientID": "your-claude-client-id",
    "ClaudeClientSecret": "your-claude-client-secret",
    "VSCodeClientID": "your-vscode-client-id",
    "VSCodeClientSecret": "your-vscode-client-secret",
    "Authority": "https://your-domain.aprimo.com/login/connect/authorize",
    "Audience": "your-domain.aprimo.com",
    "RequireHttps": true,
    "ValidateIssuer": true,
    "ValidateAudience": true,
    "ValidateLifetime": true,
    "ValidateIssuerSigningKey": true,
    "Scopes": {
      "Required": [ "api" ],
      "Supported": [ "api" ]
    }
  }
}
```

### Configuration Values Explained

| Setting | Description | Required |
|---------|-------------|----------|
| `ClaudeClientID` | Pre-configured client ID for Claude Desktop | Yes |
| `ClaudeClientSecret` | Client secret for Claude Desktop (injected by proxy) | Yes |
| `VSCodeClientID` | Pre-configured client ID for VS Code | Yes |
| `VSCodeClientSecret` | Client secret for VS Code (injected by proxy) | Yes |
| `Authority` | Full URL to the authorization server's authorize endpoint | Yes |
| `Audience` | The audience claim expected in JWT tokens | Yes |
| `RequireHttps` | Whether to require HTTPS for metadata discovery | Yes |
| `ValidateIssuer` | Whether to validate JWT token issuer | Yes |
| `ValidateAudience` | Whether to validate JWT token audience | Yes |
| `ValidateLifetime` | Whether to validate token expiration | Yes |
| `ValidateIssuerSigningKey` | Whether to validate JWT signature | Yes |
| `Scopes:Required` | List of required scopes for accessing the MCP endpoint | Yes |
| `Scopes:Supported` | List of supported scopes advertised to clients | Yes |

### Aprimo Configuration

```json
{
  "Aprimo": {
    "Domain": "your-aprimo-domain"
  }
}
```

| Setting | Description | Required |
|---------|-------------|----------|
| `Domain` | Your Aprimo domain (e.g., "productstrategy1") | Yes |

### Logging Configuration

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    },
    "FileLogging": {
      "Directory": "Logs",
      "FileName": "requests.log"
    }
  }
}
```

## How to Run

### Prerequisites

- **.NET 8.0 SDK** or later - Download from [dotnet.microsoft.com](https://dotnet.microsoft.com/download)
- **Code Editor** - Visual Studio 2022, VS Code, or JetBrains Rider
- **Configuration** - Valid `appsettings.json` with OAuth and Aprimo settings

### Step-by-Step Setup

1. **Clone or download** this repository:
   ```bash
   git clone <repository-url>
   cd remote-http-mcp-server
   ```

2. **Configure the application**:
   - Copy `appsettings.json` and update with your OAuth and Aprimo settings
   - Ensure all required configuration values are set

3. **Restore NuGet packages**:
   ```bash
   dotnet restore
   ```

4. **Build the application**:
   ```bash
   dotnet build
   ```

5. **Run the application**:
   ```bash
   dotnet run
   ```

   The server will start and listen on:
   - **HTTP**: `http://localhost:5000` (or the port configured in `launchSettings.json`)
   - **HTTPS**: `https://localhost:5001` (if configured)

6. **Verify the server is running**:
   - Check the console output for startup messages
   - Access the OAuth metadata endpoint: `http://localhost:5000/.well-known/oauth-protected-resource`
   - Access the authorization server metadata: `http://localhost:5000/.well-known/oauth-authorization-server`

### Running in Production

For production deployments:

1. Set `ASPNETCORE_ENVIRONMENT=Production`
2. Ensure HTTPS is properly configured
3. Set `OAuth:RequireHttps` to `true`
4. Configure proper logging and monitoring
5. Review and secure all configuration values

## Example Commands

### Testing OAuth Metadata Endpoints

**Get Protected Resource Metadata:**
```bash
curl http://localhost:5000/.well-known/oauth-protected-resource
```

**Get Authorization Server Metadata:**
```bash
curl http://localhost:5000/.well-known/oauth-authorization-server
```

**Get OpenID Connect Configuration:**
```bash
curl http://localhost:5000/.well-known/openid-configuration
```

### Testing the MCP Endpoint

**Without Authentication (should return 401):**
```bash
curl -X POST http://localhost:5000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

**With Authentication:**
```bash
curl -X POST http://localhost:5000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### Testing Dynamic Client Registration

```bash
curl -X POST http://localhost:5000/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Claude",
    "redirect_uris": ["http://localhost:3000/callback"],
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "api offline_access"
  }'
```

## How Authentication Works

This project implements an **OAuth proxy pattern** where the server acts as both an OAuth proxy (intermediary for authentication) and a protected resource server (hosting the MCP endpoint). The proxy sits between AI clients and the enterprise authorization server, performing request transformation and compatibility bridging.

### Architecture Diagram

```
┌─────────────────┐          ┌───────────────────────────────────────────────┐         ┌─────────────────────┐
│   AI Client     │────────▶│  Proxy & Resource Server (This Project)        │───────▶│  Authorization      │
│ (Claude Desktop)│          │  ┌──────────────────────────────────────────┐ │         │  Server (Aprimo)    │
└─────────────────┘          │  │  OAuth Proxy Endpoints:                  │ │         └─────────────────────┘
                             │  │  • /connect/authorize (proxy)            │ │
                             │  │  • /connect/token (proxy)                │ │
                             │  │  • /connect/register (DCR emulation)     │ │
                             │  │  • /.well-known/* (metadata)             │ │
                             │  └──────────────────────────────────────────┘ │
                             │  ┌──────────────────────────────────────────┐ │
                             │  │  Protected Resource:                     │ │
                             │  │  • /mcp (MCP endpoint - requires auth)   │ │
                             │  └──────────────────────────────────────────┘ │
                             └───────────────────────────────────────────────┘
```

### Authentication Flow

The authentication process follows these steps:

#### 1. Discovery Phase

The AI client discovers the OAuth endpoints by requesting metadata:

```
AI Client → GET /.well-known/oauth-protected-resource
         → GET /.well-known/oauth-authorization-server
```

The proxy responds with its own endpoints, making it appear as the authorization server to the client.

**Key Implementation:** The `OAuthMetadataController` provides these discovery endpoints, returning metadata that points to the proxy's own endpoints rather than the real authorization server.

#### 2. Client Registration (if needed)

If the AI client requires Dynamic Client Registration:

```
AI Client → POST /connect/register
         ← { "client_id": "pre-configured-id", ... }
```

**Key Implementation:** The proxy emulates DCR by returning pre-configured client credentials from `appsettings.json`. This allows clients that expect DCR to work with authorization servers that don't support it.

#### 3. Authorization Request

The AI client initiates the authorization flow:

```
AI Client → GET /connect/authorize?client_id=...&redirect_uri=...&scope=...
         → Proxy logs and filters parameters
         → Proxy redirects to real authorization server
         → User authenticates with real authorization server
         ← Real server redirects back to AI client with authorization code
```

**Key Implementation:** The proxy:
- Logs all incoming parameters for audit purposes
- Removes proprietary parameters (like `resource`) that standard OAuth clients don't understand
- Filters and normalizes scope parameters (ensures `api` scope is always included)
- Redirects to the real authorization server with cleaned parameters

#### 4. Token Exchange

The AI client exchanges the authorization code for an access token:

```
AI Client → POST /connect/token
           {
             "grant_type": "authorization_code",
             "code": "...",
             "client_id": "...",
             "redirect_uri": "..."
           }
         → Proxy logs request
         → Proxy injects client_secret if needed (for specific clients)
         → Proxy forwards to real authorization server
         ← Real server returns access token
         ← Proxy returns token to AI client
```

**Key Implementation:** The proxy:
- Detects specific clients (Claude Desktop, VS Code) by client ID
- Conditionally injects client secrets for these clients
- Removes proprietary parameters before forwarding
- Returns the token response directly to the client

#### 5. Resource Access

The AI client uses the access token to access the MCP endpoint:

```
AI Client → POST /mcp
           Authorization: Bearer <access_token>
           {
             "jsonrpc": "2.0",
             "method": "tools/list",
             "id": 1
           }
         → JWT Bearer authentication validates token
         → McpOAuthMiddleware checks scopes
         → Request proceeds to MCP handler
         ← MCP response
```

**Key Implementation:**
- JWT Bearer authentication validates the token (issuer, audience, signature, expiration)
- `McpOAuthMiddleware` enforces scope requirements
- If authentication fails, proper `WWW-Authenticate` headers are returned per RFC 9728

### Request Transformation Details

The proxy performs several transformations to ensure compatibility:

1. **Parameter Filtering**: Removes proprietary parameters like `resource` that standard OAuth clients don't understand
2. **Scope Normalization**: Ensures required scopes (like `api`) are always included, even if the client doesn't request them
3. **Secret Injection**: For specific clients (Claude Desktop, VS Code), the proxy can inject client secrets even though these clients operate as public clients
4. **Metadata Presentation**: The proxy presents itself as the authorization server through discovery endpoints, creating a seamless experience

### Code Location

The authentication proxy logic is primarily implemented in:
- **`Controllers/OAuthMetadataController.cs`**: Contains all OAuth proxy endpoints including:
  - `/.well-known/oauth-protected-resource` - Protected resource metadata
  - `/.well-known/oauth-authorization-server` - Authorization server metadata
  - `/.well-known/openid-configuration` - OpenID Connect discovery
  - `/connect/authorize` - Authorization endpoint proxy
  - `/connect/token` - Token endpoint proxy
  - `/connect/register` - Dynamic Client Registration emulation

## Functionality

### MCP Tools

The server provides MCP tools that AI assistants can use:

- **SearchAprimo**: Executes asset search queries against Aprimo's `/search/records` endpoint with advanced filtering options

### OAuth Proxy Features

- **Transparent Compatibility**: Makes enterprise authorization systems compatible with modern AI clients
- **Intelligent Parameter Filtering**: Automatically removes proprietary parameters
- **Conditional Secret Injection**: Enables public clients to work with systems requiring confidential clients
- **Comprehensive Logging**: All authentication requests are logged with timestamps and parameters
- **Standards Compliance**: Fully compliant with OAuth 2.1, RFC 8414, RFC 9728, and RFC 7591

### Security Features

- **JWT Token Validation**: Validates issuer, audience, signature, and expiration
- **Scope Enforcement**: Ensures clients have required scopes before accessing resources
- **Parameter Filtering**: Removes potentially sensitive or incompatible parameters
- **Audit Logging**: Comprehensive logging of all authentication requests
- **HTTPS Enforcement**: Requires HTTPS in production environments

## Project Structure

```
remote-http-mcp-server/
├── Controllers/
│   └── OAuthMetadataController.cs    # OAuth proxy endpoints
├── Middleware/
│   ├── McpOAuthMiddleware.cs         # OAuth scope enforcement
│   └── RequestLoggingMiddleware.cs   # Request logging
├── Services/
│   ├── AprimoService.cs              # Aprimo API integration
│   └── RequestLoggingService.cs      # Logging service
├── Tools/
│   ├── AprimoTool.cs                 # MCP tools for Aprimo
│   └── EchoTool.cs                   # Example MCP tool
├── Program.cs                        # Application startup
├── appsettings.json                  # Configuration
└── README.md                         # This file
```

## Additional Resources

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [OAuth 2.1 Specification](https://oauth.net/2.1/)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [ASP.NET Core Documentation](https://docs.microsoft.com/en-us/aspnet/core/)

## License

See LICENSE file for details.
