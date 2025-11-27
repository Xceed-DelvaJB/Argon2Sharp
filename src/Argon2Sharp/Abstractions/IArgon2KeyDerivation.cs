namespace Argon2Sharp.Abstractions;

/// <summary>
/// Defines the contract for Argon2-based key derivation operations.
/// Used for deriving cryptographic keys from passwords (KDF functionality).
/// </summary>
public interface IArgon2KeyDerivation
{
    /// <summary>
    /// Derives a cryptographic key from the password using Argon2.
    /// </summary>
    /// <param name="password">The password to derive key from.</param>
    /// <param name="salt">The salt bytes (minimum 8 bytes, recommended 16+).</param>
    /// <param name="keyLength">Desired key length in bytes.</param>
    /// <returns>Derived key bytes.</returns>
    byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int keyLength);

    /// <summary>
    /// Derives a cryptographic key from the password into the provided buffer.
    /// </summary>
    /// <param name="password">The password to derive key from.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="output">Output buffer for the derived key.</param>
    void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> output);

    /// <summary>
    /// Derives a cryptographic key from the password string.
    /// </summary>
    /// <param name="password">The password string (UTF-8 encoded).</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="keyLength">Desired key length in bytes.</param>
    /// <returns>Derived key bytes.</returns>
    byte[] DeriveKey(string password, ReadOnlySpan<byte> salt, int keyLength);

    /// <summary>
    /// Asynchronously derives a cryptographic key from the password.
    /// </summary>
    /// <param name="password">The password to derive key from.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="keyLength">Desired key length in bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Derived key bytes.</returns>
    ValueTask<byte[]> DeriveKeyAsync(ReadOnlyMemory<byte> password, ReadOnlyMemory<byte> salt, int keyLength, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously derives a cryptographic key from the password string.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="keyLength">Desired key length in bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Derived key bytes.</returns>
    ValueTask<byte[]> DeriveKeyAsync(string password, ReadOnlyMemory<byte> salt, int keyLength, CancellationToken cancellationToken = default);
}
