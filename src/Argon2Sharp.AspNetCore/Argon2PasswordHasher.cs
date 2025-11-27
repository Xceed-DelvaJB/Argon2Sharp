using Microsoft.AspNetCore.Identity;

namespace Argon2Sharp.AspNetCore;

/// <summary>
/// Argon2-based password hasher for ASP.NET Core Identity.
/// </summary>
/// <typeparam name="TUser">The type of user.</typeparam>
/// <remarks>
/// <para>This class implements <see cref="IPasswordHasher{TUser}"/> to provide
/// Argon2 password hashing for ASP.NET Core Identity applications.</para>
/// <para>Features:</para>
/// <list type="bullet">
/// <item>Automatic hash upgrade when parameters change</item>
/// <item>Compatible with existing Identity password verification</item>
/// <item>Configurable Argon2 parameters</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // In Startup.cs or Program.cs
/// services.AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
///     .AddEntityFrameworkStores&lt;ApplicationDbContext&gt;()
///     .AddArgon2PasswordHasher();
/// </code>
/// </example>
public sealed class Argon2PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private readonly Argon2PasswordHasherOptions _options;
    private readonly Argon2RehashService _rehashService;

    /// <summary>
    /// Creates a new instance with default options.
    /// </summary>
    public Argon2PasswordHasher() : this(new Argon2PasswordHasherOptions())
    {
    }

    /// <summary>
    /// Creates a new instance with specified options.
    /// </summary>
    /// <param name="options">Password hasher options.</param>
    public Argon2PasswordHasher(Argon2PasswordHasherOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _rehashService = new Argon2RehashService();
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var parameters = _options.GetParameters();
        return Argon2PhcFormat.HashToPhcStringWithAutoSalt(password, parameters);
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(hashedPassword);
        ArgumentNullException.ThrowIfNull(providedPassword);

        // Try to verify as Argon2 PHC format
        if (hashedPassword.StartsWith("$argon2", StringComparison.Ordinal))
        {
            return VerifyArgon2Hash(hashedPassword, providedPassword);
        }

        // Fallback: might be a legacy hash format (e.g., ASP.NET Identity v3)
        // Return Failed - the application should handle migration
        return PasswordVerificationResult.Failed;
    }

    private PasswordVerificationResult VerifyArgon2Hash(string hashedPassword, string providedPassword)
    {
        var (isValid, extractedParams) = Argon2PhcFormat.VerifyPhcString(providedPassword, hashedPassword);

        if (!isValid)
        {
            return PasswordVerificationResult.Failed;
        }

        // Check if rehash is needed
        if (_options.EnableAutoRehash && extractedParams != null)
        {
            var checkResult = _rehashService.CheckNeedsRehash(hashedPassword, _options.GetParameters());
            if (checkResult.NeedsRehash)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
        }

        return PasswordVerificationResult.Success;
    }
}

/// <summary>
/// Options for configuring the Argon2 password hasher.
/// </summary>
public sealed class Argon2PasswordHasherOptions
{
    /// <summary>
    /// Memory size in kilobytes. Default: 19456 KB (19 MB).
    /// </summary>
    public int MemorySizeKB { get; set; } = 19456;

    /// <summary>
    /// Number of iterations. Default: 2.
    /// </summary>
    public int Iterations { get; set; } = 2;

    /// <summary>
    /// Degree of parallelism. Default: 1.
    /// </summary>
    public int Parallelism { get; set; } = 1;

    /// <summary>
    /// Output hash length in bytes. Default: 32.
    /// </summary>
    public int HashLength { get; set; } = 32;

    /// <summary>
    /// Argon2 variant to use. Default: Argon2id.
    /// </summary>
    public Argon2Type Type { get; set; } = Argon2Type.Argon2id;

    /// <summary>
    /// Whether to automatically indicate rehash is needed when parameters change.
    /// Default: true.
    /// </summary>
    public bool EnableAutoRehash { get; set; } = true;

    /// <summary>
    /// Gets the Argon2Parameters based on current options.
    /// </summary>
    /// <returns>Configured parameters.</returns>
    internal Argon2Parameters GetParameters()
    {
        return Argon2Parameters.CreateBuilder()
            .WithType(Type)
            .WithMemorySizeKB(MemorySizeKB)
            .WithIterations(Iterations)
            .WithParallelism(Parallelism)
            .WithHashLength(HashLength)
            .Build();
    }
}
