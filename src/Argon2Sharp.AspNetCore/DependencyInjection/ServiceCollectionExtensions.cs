using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Argon2Sharp.AspNetCore;

/// <summary>
/// Extension methods for configuring Argon2Sharp services in ASP.NET Core.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Argon2Sharp password hasher to the Identity configuration.
    /// </summary>
    /// <typeparam name="TUser">The user type.</typeparam>
    /// <param name="builder">The Identity builder.</param>
    /// <returns>The Identity builder for chaining.</returns>
    /// <example>
    /// <code>
    /// services.AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
    ///     .AddEntityFrameworkStores&lt;ApplicationDbContext&gt;()
    ///     .AddArgon2PasswordHasher();
    /// </code>
    /// </example>
    public static IdentityBuilder AddArgon2PasswordHasher<TUser>(this IdentityBuilder builder)
        where TUser : class
    {
        builder.Services.TryAddScoped<IPasswordHasher<TUser>, Argon2PasswordHasher<TUser>>();
        return builder;
    }

    /// <summary>
    /// Adds Argon2Sharp password hasher with custom options to the Identity configuration.
    /// </summary>
    /// <typeparam name="TUser">The user type.</typeparam>
    /// <param name="builder">The Identity builder.</param>
    /// <param name="configure">Action to configure password hasher options.</param>
    /// <returns>The Identity builder for chaining.</returns>
    /// <example>
    /// <code>
    /// services.AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
    ///     .AddEntityFrameworkStores&lt;ApplicationDbContext&gt;()
    ///     .AddArgon2PasswordHasher(options =>
    ///     {
    ///         options.MemorySizeKB = 65536;
    ///         options.Iterations = 4;
    ///         options.Parallelism = 4;
    ///     });
    /// </code>
    /// </example>
    public static IdentityBuilder AddArgon2PasswordHasher<TUser>(
        this IdentityBuilder builder,
        Action<Argon2PasswordHasherOptions> configure)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new Argon2PasswordHasherOptions();
        configure(options);

        builder.Services.TryAddScoped<IPasswordHasher<TUser>>(_ => new Argon2PasswordHasher<TUser>(options));
        return builder;
    }

    /// <summary>
    /// Adds Argon2Sharp core services to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <example>
    /// <code>
    /// services.AddArgon2Sharp();
    /// </code>
    /// </example>
    public static IServiceCollection AddArgon2Sharp(this IServiceCollection services)
    {
        return AddArgon2Sharp(services, _ => { });
    }

    /// <summary>
    /// Adds Argon2Sharp core services with custom configuration to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure Argon2 options.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <example>
    /// <code>
    /// services.AddArgon2Sharp(options =>
    /// {
    ///     options.DefaultMemorySizeKB = 65536;
    ///     options.DefaultIterations = 4;
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddArgon2Sharp(
        this IServiceCollection services,
        Action<Argon2ServiceOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new Argon2ServiceOptions();
        configure(options);

        // Register core services
        services.TryAddSingleton(options.GetDefaultParameters());
        services.TryAddSingleton<Argon2KeyDerivation>();
        services.TryAddSingleton<Argon2ParameterTuner>();
        services.TryAddSingleton<Argon2RehashService>();
        services.TryAddSingleton<Argon2BatchHasher>();
        services.TryAddSingleton<Argon2AsyncHasher>();

        return services;
    }
}

/// <summary>
/// Options for configuring Argon2Sharp services.
/// </summary>
public sealed class Argon2ServiceOptions
{
    /// <summary>
    /// Default memory size in kilobytes. Default: 19456 KB (19 MB).
    /// </summary>
    public int DefaultMemorySizeKB { get; set; } = 19456;

    /// <summary>
    /// Default number of iterations. Default: 2.
    /// </summary>
    public int DefaultIterations { get; set; } = 2;

    /// <summary>
    /// Default degree of parallelism. Default: 1.
    /// </summary>
    public int DefaultParallelism { get; set; } = 1;

    /// <summary>
    /// Default output hash length in bytes. Default: 32.
    /// </summary>
    public int DefaultHashLength { get; set; } = 32;

    /// <summary>
    /// Default Argon2 variant. Default: Argon2id.
    /// </summary>
    public Argon2Type DefaultType { get; set; } = Argon2Type.Argon2id;

    /// <summary>
    /// Gets the default Argon2Parameters based on current options.
    /// </summary>
    internal Argon2Parameters GetDefaultParameters()
    {
        return Argon2Parameters.CreateBuilder()
            .WithType(DefaultType)
            .WithMemorySizeKB(DefaultMemorySizeKB)
            .WithIterations(DefaultIterations)
            .WithParallelism(DefaultParallelism)
            .WithHashLength(DefaultHashLength)
            .Build();
    }
}
