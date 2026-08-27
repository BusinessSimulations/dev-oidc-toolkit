namespace DevOidcToolkit.UnitTests.Infrastructure.Configuration;

using System;
using System.Collections.Generic;

using DevOidcToolkit.Infrastructure.Configuration;

using Microsoft.Extensions.Configuration;

using Xunit;

public class AccessTokenFormatConfigurationTests
{
    private static DevOidcToolkitConfiguration Bind(Dictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        return configuration.GetSection(DevOidcToolkitConfiguration.Position).Get<DevOidcToolkitConfiguration>()
            ?? new DevOidcToolkitConfiguration();
    }

    [Fact]
    public void DefaultsToJwtWhenNotConfigured()
    {
        var config = Bind([]);

        Assert.Equal(AccessTokenFormat.Jwt, config.AccessTokenFormat);
    }

    [Theory]
    [InlineData("Jwt", AccessTokenFormat.Jwt)]
    [InlineData("Opaque", AccessTokenFormat.Opaque)]
    [InlineData("opaque", AccessTokenFormat.Opaque)]
    public void BindsTheConfiguredFormat(string value, AccessTokenFormat expected)
    {
        var config = Bind(new Dictionary<string, string?>
        {
            ["DevOidcToolkit:AccessTokenFormat"] = value
        });

        Assert.Equal(expected, config.AccessTokenFormat);
    }

    [Fact]
    public void ThrowsForAnUnrecognisedFormat()
    {
        var exception = Record.Exception(() => Bind(new Dictionary<string, string?>
        {
            ["DevOidcToolkit:AccessTokenFormat"] = "RsaOaep"
        }));

        Assert.NotNull(exception);
    }
}