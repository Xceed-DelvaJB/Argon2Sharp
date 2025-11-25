using Argon2Sharp.Core;
using System.Security.Cryptography;
using System.Text;

namespace Argon2Sharp;

/// <summary>
/// Main Argon2 hasher class providing high-level API.
/// Pure C# implementation of Argon2d, Argon2i, and Argon2id password hashing algorithms.
/// Based on RFC 9106 specification.
/// </summary>
/// <remarks>
/// <para>This class provides both instance-based and static methods for Argon2 hashing.</para>
/// <para>For most use cases, consider using <see cref="Argon2PhcFormat"/> for PHC-format string output.</para>
/// </remarks>
/// <example>
/// <code>
/// // Instance-based hashing with Span API (recommended)
/// var parameters = Argon2Parameters.CreateBuilder()
///     .WithRandomSalt()
///     .Build();
/// var argon2 = new Argon2(parameters);
/// byte[] hash = argon2.Hash("password");
/// 
/// // Static convenience method
/// var (hash, salt) = Argon2.HashPasswordWithSalt("password");
/// </code>
/// </example>
public sealed class Argon2
{
    private readonly Argon2Parameters _parameters;

    /// <summary>
    /// Creates an Argon2 hasher with specified parameters.
    /// </summary>
    /// <param name="parameters">Argon2 parameters to use for hashing.</param>
    /// <exception cref="ArgumentNullException">Thrown when parameters is null.</exception>
    public Argon2(Argon2Parameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    #region Primary Span-based API

    /// <summary>
    /// Computes Argon2 hash of the password into the provided output buffer.
    /// This is the primary hashing method using Span for optimal performance.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <param name="output">Output buffer to write hash to. Must be exactly <see cref="Argon2Parameters.HashLength"/> bytes.</param>
    /// <exception cref="ArgumentException">Thrown when output buffer size doesn't match HashLength.</exception>
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
    {
        if (output.Length != _parameters.HashLength)
            throw new ArgumentException($"Output buffer must be {_parameters.HashLength} bytes", nameof(output));

        var engine = new Argon2Engine(_parameters);
        engine.Hash(password, output);
    }

    /// <summary>
    /// Computes Argon2 hash of the password.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <returns>Hash bytes of length specified in parameters.</returns>
    public byte[] Hash(ReadOnlySpan<byte> password)
    {
        byte[] output = new byte[_parameters.HashLength];
        Hash(password, output);
        return output;
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash using Span types.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password bytes to verify.</param>
    /// <param name="hash">Expected hash to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    public bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<byte> hash)
    {
        if (hash.Length != _parameters.HashLength)
            return false;

        Span<byte> computed = _parameters.HashLength <= 256 
            ? stackalloc byte[_parameters.HashLength] 
            : new byte[_parameters.HashLength];
        
        Hash(password, computed);
        return CryptographicOperations.FixedTimeEquals(computed, hash);
    }

    #endregion

    #region String convenience methods

    /// <summary>
    /// Computes Argon2 hash of the password.
    /// </summary>
    /// <param name="password">Password string to hash (UTF-8 encoded).</param>
    /// <returns>Hash bytes of length specified in parameters.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    public byte[] Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Hash(Encoding.UTF8.GetBytes(password).AsSpan());
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password string to verify (UTF-8 encoded).</param>
    /// <param name="hash">Expected hash to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    public bool Verify(string password, ReadOnlySpan<byte> hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Verify(Encoding.UTF8.GetBytes(password).AsSpan(), hash);
    }

    #endregion

    #region Obsolete byte[] methods (v2.x compatibility)

    /// <summary>
    /// Computes Argon2 hash of the password.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <returns>Hash bytes of length specified in parameters.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    [Obsolete("Use Hash(ReadOnlySpan<byte>) instead for better performance. This method will be removed in v4.0.")]
    public byte[] Hash(byte[] password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Hash(password.AsSpan());
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password string to verify.</param>
    /// <param name="hash">Hash bytes to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or hash is null.</exception>
    [Obsolete("Use Verify(string, ReadOnlySpan<byte>) instead. This method will be removed in v4.0.")]
    public bool Verify(string password, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);
        return Verify(Encoding.UTF8.GetBytes(password).AsSpan(), hash.AsSpan());
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password bytes to verify.</param>
    /// <param name="hash">Hash bytes to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or hash is null.</exception>
    [Obsolete("Use Verify(ReadOnlySpan<byte>, ReadOnlySpan<byte>) instead. This method will be removed in v4.0.")]
    public bool Verify(byte[] password, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);
        return Verify(password.AsSpan(), hash.AsSpan());
    }

    #endregion

    #region Static convenience methods

    /// <summary>
    /// Hashes a password with default parameters (Argon2id) and returns both hash and generated salt.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="parameters">Optional parameters (uses CreateDefault() if null). Salt will be generated if not provided.</param>
    /// <returns>A tuple containing the hash and the salt used.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    public static (byte[] Hash, byte[] Salt) HashPasswordWithSalt(string password, Argon2Parameters? parameters = null)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        var salt = GenerateSalt(16);
        var p = (parameters ?? Argon2Parameters.CreateDefault()) with { Salt = salt };
        
        var argon2 = new Argon2(p);
        var hash = argon2.Hash(password);
        
        return (hash, salt);
    }

    /// <summary>
    /// Hashes a password with default parameters (Argon2id).
    /// Generates a random 16-byte salt automatically.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="salt">Generated salt (output).</param>
    /// <returns>Hash bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    [Obsolete("Use HashPasswordWithSalt(string, Argon2Parameters?) instead which returns a tuple. This method will be removed in v4.0.")]
    public static byte[] HashPassword(string password, out byte[] salt)
    {
        var result = HashPasswordWithSalt(password);
        salt = result.Salt;
        return result.Hash;
    }

    /// <summary>
    /// Hashes a password with specified parameters.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="salt">Salt to use (minimum 8 bytes).</param>
    /// <param name="memorySizeKB">Memory size in KB.</param>
    /// <param name="iterations">Number of iterations.</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="hashLength">Output hash length in bytes.</param>
    /// <param name="type">Argon2 type (default: Argon2id).</param>
    /// <returns>Hash bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or salt is null.</exception>
    [Obsolete("Use Argon2Parameters.CreateBuilder() with fluent API instead. This method will be removed in v4.0.")]
    public static byte[] HashPassword(
        string password,
        byte[] salt,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        int hashLength = 32,
        Argon2Type type = Argon2Type.Argon2id)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);

        var parameters = new Argon2Parameters
        {
            Type = type,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hashLength,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        return argon2.Hash(password);
    }

    /// <summary>
    /// Verifies a password against a hash with the same parameters.
    /// </summary>
    /// <param name="password">Password to verify.</param>
    /// <param name="hash">Hash to verify against.</param>
    /// <param name="salt">Salt used in hashing.</param>
    /// <param name="memorySizeKB">Memory size in KB.</param>
    /// <param name="iterations">Number of iterations.</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="type">Argon2 type.</param>
    /// <returns>True if password matches, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password, hash, or salt is null.</exception>
    [Obsolete("Use Argon2Parameters.CreateBuilder() with fluent API instead. This method will be removed in v4.0.")]
    public static bool VerifyPassword(
        string password,
        byte[] hash,
        byte[] salt,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        Argon2Type type = Argon2Type.Argon2id)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(salt);

        var parameters = new Argon2Parameters
        {
            Type = type,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hash.Length,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        return argon2.Verify(password, hash.AsSpan());
    }

    /// <summary>
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="length">Salt length in bytes (minimum 8, recommended 16).</param>
    /// <returns>Random salt bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when length is less than 8.</exception>
    public static byte[] GenerateSalt(int length = 16)
    {
        if (length < 8)
            throw new ArgumentException("Salt length must be at least 8 bytes", nameof(length));

        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// Converts hash bytes to Base64 string for storage.
    /// </summary>
    /// <param name="hash">Hash bytes to convert.</param>
    /// <returns>Base64-encoded string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when hash is null.</exception>
    public static string ToBase64(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Converts Base64 string back to hash bytes.
    /// </summary>
    /// <param name="base64Hash">Base64-encoded hash string.</param>
    /// <returns>Hash bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when base64Hash is null.</exception>
    /// <exception cref="FormatException">Thrown when base64Hash is not valid Base64.</exception>
    public static byte[] FromBase64(string base64Hash)
    {
        ArgumentNullException.ThrowIfNull(base64Hash);
        return Convert.FromBase64String(base64Hash);
    }

    #endregion
}
