namespace Argon2Sharp.Abstractions;

/// <summary>
/// Defines the contract for automatic password hash rehashing/upgrading.
/// </summary>
public interface IArgon2RehashService
{
    /// <summary>
    /// Checks if a PHC hash string needs to be rehashed based on minimum parameters.
    /// </summary>
    /// <param name="phcHash">The PHC-formatted hash string to check.</param>
    /// <param name="minimumParameters">The minimum acceptable parameters.</param>
    /// <returns>Result indicating if rehash is needed and why.</returns>
    RehashCheckResult CheckNeedsRehash(string phcHash, Argon2Parameters minimumParameters);

    /// <summary>
    /// Rehashes a password if the current hash doesn't meet minimum parameters.
    /// </summary>
    /// <param name="password">The password to verify and potentially rehash.</param>
    /// <param name="currentPhcHash">The current PHC hash to verify against.</param>
    /// <param name="targetParameters">The target parameters for the new hash.</param>
    /// <returns>Result containing the new hash if rehashed, or the original if no rehash needed.</returns>
    RehashResult RehashIfNeeded(string password, string currentPhcHash, Argon2Parameters targetParameters);

    /// <summary>
    /// Asynchronously rehashes a password if the current hash doesn't meet minimum parameters.
    /// </summary>
    /// <param name="password">The password to verify and potentially rehash.</param>
    /// <param name="currentPhcHash">The current PHC hash to verify against.</param>
    /// <param name="targetParameters">The target parameters for the new hash.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Result containing the new hash if rehashed, or the original if no rehash needed.</returns>
    ValueTask<RehashResult> RehashIfNeededAsync(string password, string currentPhcHash, Argon2Parameters targetParameters, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies and optionally rehashes in a single operation.
    /// </summary>
    /// <param name="password">The password to verify.</param>
    /// <param name="currentPhcHash">The current PHC hash.</param>
    /// <param name="targetParameters">Target parameters for potential rehash.</param>
    /// <returns>Tuple of (isValid, newHash or null if not rehashed).</returns>
    (bool IsValid, string? NewHash) VerifyAndRehash(string password, string currentPhcHash, Argon2Parameters targetParameters);

    /// <summary>
    /// Asynchronously verifies and optionally rehashes in a single operation.
    /// </summary>
    /// <param name="password">The password to verify.</param>
    /// <param name="currentPhcHash">The current PHC hash.</param>
    /// <param name="targetParameters">Target parameters for potential rehash.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Tuple of (isValid, newHash or null if not rehashed).</returns>
    ValueTask<(bool IsValid, string? NewHash)> VerifyAndRehashAsync(string password, string currentPhcHash, Argon2Parameters targetParameters, CancellationToken cancellationToken = default);
}
