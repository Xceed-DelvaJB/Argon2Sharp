using Argon2Sharp.Core;
using System.Security.Cryptography;
using System.Text;

namespace Argon2Sharp;

/// <summary>
/// Main Argon2 hasher class providing high-level API.
/// Pure C# implementation of Argon2d, Argon2i, and Argon2id password hashing algorithms.
/// Based on RFC 9106 specification.
/// </summary>
public sealed class Argon2
{
    private readonly Argon2Parameters _parameters;

    /// <summary>
    /// Creates an Argon2 hasher with specified parameters.
    /// </summary>
    /// <param name="parameters">Argon2 parameters to use for hashing.</param>
    public Argon2(Argon2Parameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    /// <summary>
    /// Computes Argon2 hash of the password.
    /// </summary>
    /// <param name="password">Password to hash (UTF-8 encoded if string).</param>
    /// <returns>Hash bytes of length specified in parameters.</returns>
    public byte[] Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Hash(Encoding.UTF8.GetBytes(password));
    }

    /// <summary>
    /// Computes Argon2 hash of the password.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <returns>Hash bytes of length specified in parameters.</returns>
    public byte[] Hash(byte[] password)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        byte[] output = new byte[_parameters.HashLength];
        Hash(password, output);
        return output;
    }

    /// <summary>
    /// Computes Argon2 hash of the password into the provided output buffer.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="output">Output buffer to write hash to.</param>
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
    {
        if (output.Length != _parameters.HashLength)
            throw new ArgumentException($"Output buffer must be {_parameters.HashLength} bytes", nameof(output));

        var engine = new Argon2Engine(_parameters);
        engine.Hash(password, output);
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password to verify.</param>
    /// <param name="hash">Hash to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    public bool Verify(string password, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Verify(Encoding.UTF8.GetBytes(password), hash);
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Password bytes to verify.</param>
    /// <param name="hash">Hash to verify against.</param>
    /// <returns>True if password matches hash, false otherwise.</returns>
    public bool Verify(byte[] password, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);

        if (hash.Length != _parameters.HashLength)
            return false;

        byte[] computed = Hash(password);
        return CryptographicOperations.FixedTimeEquals(computed, hash);
    }

    /// <summary>
    /// Hashes a password with default parameters (Argon2id).
    /// Generates a random 16-byte salt automatically.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="salt">Generated salt (output).</param>
    /// <returns>Hash bytes.</returns>
    public static byte[] HashPassword(string password, out byte[] salt)
    {
        salt = GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateDefault();
        parameters.Salt = salt;
        
        var argon2 = new Argon2(parameters);
        return argon2.Hash(password);
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
    public static byte[] HashPassword(
        string password,
        byte[] salt,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        int hashLength = 32,
        Argon2Type type = Argon2Type.Argon2id)
    {
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
    public static bool VerifyPassword(
        string password,
        byte[] hash,
        byte[] salt,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        Argon2Type type = Argon2Type.Argon2id)
    {
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
        return argon2.Verify(password, hash);
    }

    /// <summary>
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="length">Salt length in bytes (minimum 8, recommended 16).</param>
    /// <returns>Random salt bytes.</returns>
    public static byte[] GenerateSalt(int length = 16)
    {
        if (length < 8)
            throw new ArgumentException("Salt length must be at least 8 bytes", nameof(length));

        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// Converts hash bytes to Base64 string for storage.
    /// </summary>
    public static string ToBase64(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Converts Base64 string back to hash bytes.
    /// </summary>
    public static byte[] FromBase64(string base64Hash)
    {
        ArgumentNullException.ThrowIfNull(base64Hash);
        return Convert.FromBase64String(base64Hash);
    }
}
