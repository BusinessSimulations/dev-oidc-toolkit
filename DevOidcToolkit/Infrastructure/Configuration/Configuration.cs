namespace DevOidcToolkit.Infrastructure.Configuration;

using System;
using System.ComponentModel.DataAnnotations;

using Microsoft.Extensions.Options;

public class DevOidcToolkitConfiguration
{
    public const string Position = "DevOidcToolkit";

    public int Port { get; set; } = 80;
    public string? Address { get; set; }
    public string? Issuer { get; set; }

    [ValidateObjectMembers] public List<UserConfiguration> Users { get; set; } = [];
    [ValidateObjectMembers] public List<ClientConfiguration> Clients { get; set; } = [];

    [ValidateObjectMembers] public HttpsConfiguration? Https { get; set; }
    [ValidateObjectMembers] public LoggingConfiguration Logging { get; set; } = new LoggingConfiguration();
}

public class UserConfiguration
{
    [Required] public required string Email { get; set; }
    [Required] public required string FirstName { get; set; }
    [Required] public required string LastName { get; set; }
    public List<string> Roles { get; set; } = [];
}

public class ClientConfiguration
{
    [Required] public required string Id { get; set; }
    [Required] public required string Secret { get; set; }

    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
}

public class HttpsConfiguration
{
    [ValidateObjectMembers] public FileHttpsConfiguration? File { get; set; }
    [ValidateObjectMembers] public InlineHttpsConfiguration? Inline { get; set; }
}

public class FileHttpsConfiguration
{
    [Required] public required string CertificatePath { get; set; }
    [Required] public required string PrivateKeyPath { get; set; }
}

public class InlineHttpsConfiguration
{
    [Required] public required string Certificate { get; set; }
    [Required] public required string PrivateKey { get; set; }
}

public class UnknownLogEventLevelException(string? message) : Exception(message)
{ }

public class LogEventLevelMapping
{
    public static LogLevel LogLevelType(LogEventLevel level)
    {
        return level switch
        {
            LogEventLevel.Trace => LogLevel.Trace,
            LogEventLevel.Debug => LogLevel.Debug,
            LogEventLevel.Information => LogLevel.Information,
            LogEventLevel.Warning => LogLevel.Warning,
            LogEventLevel.Error => LogLevel.Error,
            LogEventLevel.Fatal => LogLevel.Critical,
            _ => throw new UnknownLogEventLevelException($"Unknown log event level: {level}")
        };
    }
}

public enum LogEventLevel
{
    Trace,
    Debug,
    Information,
    Warning,
    Error,
    Fatal
}

public class LoggingConfiguration
{
    public LogEventLevel MinimumLevel { get; set; } = LogEventLevel.Information;
    public bool UseXForwardedForHeader { get; set; } = false;
}