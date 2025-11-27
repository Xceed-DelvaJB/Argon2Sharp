namespace Argon2Sharp.Abstractions;

/// <summary>
/// Defines the contract for asynchronous Argon2 password hashing operations.
/// </summary>
public interface IArgon2AsyncHasher : IArgon2Hasher
{
    /// <summary>
    /// Asynchronously computes the Argon2 hash of the password.
    /// </summary>
    /// <param name="password">The password bytes to hash.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task containing the computed hash.</returns>
    ValueTask<byte[]> HashAsync(ReadOnlyMemory<byte> password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously computes the Argon2 hash of the password string.
    /// </summary>
    /// <param name="password">The password string to hash (UTF-8 encoded).</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task containing the computed hash.</returns>
    ValueTask<byte[]> HashAsync(string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously verifies a password against a hash.
    /// </summary>
    /// <param name="password">The password bytes to verify.</param>
    /// <param name="hash">The hash to verify against.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task containing true if the password matches, false otherwise.</returns>
    ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> password, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously verifies a password string against a hash.
    /// </summary>
    /// <param name="password">The password string to verify (UTF-8 encoded).</param>
    /// <param name="hash">The hash to verify against.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task containing true if the password matches, false otherwise.</returns>
    ValueTask<bool> VerifyAsync(string password, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously computes the Argon2 hash with progress reporting.
    /// </summary>
    /// <param name="password">The password bytes to hash.</param>
    /// <param name="progress">Progress reporter (0.0 to 1.0).</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task containing the computed hash.</returns>
    ValueTask<byte[]> HashAsync(ReadOnlyMemory<byte> password, IProgress<double>? progress, CancellationToken cancellationToken = default);
}
