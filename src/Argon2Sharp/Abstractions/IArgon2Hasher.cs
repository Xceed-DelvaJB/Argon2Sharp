namespace Argon2Sharp.Abstractions;

/// <summary>
/// Defines the contract for Argon2 password hashing operations.
/// </summary>
public interface IArgon2Hasher
{
    /// <summary>
    /// Gets the parameters used by this hasher instance.
    /// </summary>
    Argon2Parameters Parameters { get; }

    /// <summary>
    /// Computes the Argon2 hash of the password.
    /// </summary>
    /// <param name="password">The password bytes to hash.</param>
    /// <returns>The computed hash.</returns>
    byte[] Hash(ReadOnlySpan<byte> password);

    /// <summary>
    /// Computes the Argon2 hash of the password into the provided output buffer.
    /// </summary>
    /// <param name="password">The password bytes to hash.</param>
    /// <param name="output">The output buffer for the hash.</param>
    void Hash(ReadOnlySpan<byte> password, Span<byte> output);

    /// <summary>
    /// Verifies a password against a hash.
    /// </summary>
    /// <param name="password">The password bytes to verify.</param>
    /// <param name="hash">The hash to verify against.</param>
    /// <returns>True if the password matches, false otherwise.</returns>
    bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<byte> hash);

    /// <summary>
    /// Computes the Argon2 hash of the password string.
    /// </summary>
    /// <param name="password">The password string to hash (UTF-8 encoded).</param>
    /// <returns>The computed hash.</returns>
    byte[] Hash(string password);

    /// <summary>
    /// Verifies a password string against a hash.
    /// </summary>
    /// <param name="password">The password string to verify (UTF-8 encoded).</param>
    /// <param name="hash">The hash to verify against.</param>
    /// <returns>True if the password matches, false otherwise.</returns>
    bool Verify(string password, ReadOnlySpan<byte> hash);
}
