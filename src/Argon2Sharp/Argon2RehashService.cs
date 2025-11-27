using Argon2Sharp.Abstractions;

namespace Argon2Sharp;

/// <summary>
/// Reasons why a password hash might need to be rehashed.
/// </summary>
public enum RehashReason
{
    /// <summary>No rehash needed.</summary>
    None = 0,
    
    /// <summary>Memory parameter is below minimum threshold.</summary>
    InsufficientMemory,
    
    /// <summary>Iteration count is below minimum threshold.</summary>
    InsufficientIterations,
    
    /// <summary>Parallelism differs from target.</summary>
    ParallelismMismatch,
    
    /// <summary>Hash length differs from target.</summary>
    HashLengthMismatch,
    
    /// <summary>Algorithm type differs from target.</summary>
    TypeMismatch,
    
    /// <summary>Version is outdated.</summary>
    VersionOutdated,
    
    /// <summary>Multiple parameters need updating.</summary>
    MultipleReasons
}

/// <summary>
/// Result of a rehash check operation.
/// </summary>
/// <param name="NeedsRehash">Whether the hash needs to be upgraded.</param>
/// <param name="CurrentParameters">The parameters extracted from the current hash.</param>
/// <param name="Reason">The reason why rehash is needed, if applicable.</param>
public readonly record struct RehashCheckResult(
    bool NeedsRehash,
    Argon2Parameters? CurrentParameters,
    RehashReason Reason);

/// <summary>
/// Result of a rehash operation.
/// </summary>
/// <param name="Success">Whether the operation succeeded.</param>
/// <param name="NewPhcHash">The new PHC-formatted hash string (or original if not rehashed).</param>
/// <param name="WasRehashed">Whether the hash was actually rehashed.</param>
/// <param name="NewParameters">The parameters used for the new hash.</param>
public readonly record struct RehashResult(
    bool Success,
    string? NewPhcHash,
    bool WasRehashed,
    Argon2Parameters? NewParameters);

/// <summary>
/// Service for automatic password hash rehashing/upgrading.
/// </summary>
/// <remarks>
/// <para>This service implements <see cref="IArgon2RehashService"/> to provide
/// automatic password hash upgrades as security requirements evolve.</para>
/// <para>Typical workflow:</para>
/// <list type="number">
/// <item>During login, verify password and check if rehash is needed</item>
/// <item>If valid and needs rehash, generate new hash with stronger parameters</item>
/// <item>Store the new hash in your database</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// var rehashService = new Argon2RehashService();
/// var minParams = Argon2Parameters.CreateDefault();
/// 
/// // Check and rehash during login
/// var (isValid, newHash) = rehashService.VerifyAndRehash(password, storedHash, minParams);
/// 
/// if (isValid)
/// {
///     if (newHash != null)
///     {
///         // Update database with new hash
///         await UpdateUserHash(userId, newHash);
///     }
///     // Login successful
/// }
/// </code>
/// </example>
public sealed class Argon2RehashService : IArgon2RehashService
{
    /// <inheritdoc />
    public RehashCheckResult CheckNeedsRehash(string phcHash, Argon2Parameters minimumParameters)
    {
        ArgumentNullException.ThrowIfNull(phcHash);
        ArgumentNullException.ThrowIfNull(minimumParameters);

        if (!Argon2PhcFormat.TryDecode(phcHash, out _, out var currentParams))
        {
            return new RehashCheckResult(false, null, RehashReason.None);
        }

        var reasons = new List<RehashReason>();

        // Check memory
        if (currentParams!.MemorySizeKB < minimumParameters.MemorySizeKB)
        {
            reasons.Add(RehashReason.InsufficientMemory);
        }

        // Check iterations
        if (currentParams.Iterations < minimumParameters.Iterations)
        {
            reasons.Add(RehashReason.InsufficientIterations);
        }

        // Check parallelism (if different from target)
        if (currentParams.Parallelism != minimumParameters.Parallelism)
        {
            reasons.Add(RehashReason.ParallelismMismatch);
        }

        // Check hash length
        if (currentParams.HashLength < minimumParameters.HashLength)
        {
            reasons.Add(RehashReason.HashLengthMismatch);
        }

        // Check type
        if (currentParams.Type != minimumParameters.Type)
        {
            reasons.Add(RehashReason.TypeMismatch);
        }

        // Check version
        if ((int)currentParams.Version < (int)minimumParameters.Version)
        {
            reasons.Add(RehashReason.VersionOutdated);
        }

        if (reasons.Count == 0)
        {
            return new RehashCheckResult(false, currentParams, RehashReason.None);
        }

        var reason = reasons.Count == 1 ? reasons[0] : RehashReason.MultipleReasons;
        return new RehashCheckResult(true, currentParams, reason);
    }

    /// <inheritdoc />
    public RehashResult RehashIfNeeded(string password, string currentPhcHash, Argon2Parameters targetParameters)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(currentPhcHash);
        ArgumentNullException.ThrowIfNull(targetParameters);

        // First verify the password
        var (isValid, currentParams) = Argon2PhcFormat.VerifyPhcString(password, currentPhcHash);
        
        if (!isValid)
        {
            return new RehashResult(false, null, false, null);
        }

        // Check if rehash is needed
        var checkResult = CheckNeedsRehash(currentPhcHash, targetParameters);
        
        if (!checkResult.NeedsRehash)
        {
            return new RehashResult(true, currentPhcHash, false, currentParams);
        }

        // Generate new hash with target parameters
        var newHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt(password, targetParameters);
        
        return new RehashResult(true, newHash, true, targetParameters);
    }

    /// <inheritdoc />
    public async ValueTask<RehashResult> RehashIfNeededAsync(
        string password, 
        string currentPhcHash, 
        Argon2Parameters targetParameters, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(currentPhcHash);
        ArgumentNullException.ThrowIfNull(targetParameters);

        // First verify the password asynchronously
        var (isValid, currentParams) = await Argon2AsyncHasher.VerifyPhcStringAsync(
            password, currentPhcHash, cancellationToken).ConfigureAwait(false);
        
        if (!isValid)
        {
            return new RehashResult(false, null, false, null);
        }

        // Check if rehash is needed
        var checkResult = CheckNeedsRehash(currentPhcHash, targetParameters);
        
        if (!checkResult.NeedsRehash)
        {
            return new RehashResult(true, currentPhcHash, false, currentParams);
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Generate new hash with target parameters asynchronously
        var newHash = await Argon2AsyncHasher.HashToPhcStringAsync(
            password, targetParameters, cancellationToken).ConfigureAwait(false);
        
        return new RehashResult(true, newHash, true, targetParameters);
    }

    /// <inheritdoc />
    public (bool IsValid, string? NewHash) VerifyAndRehash(
        string password, 
        string currentPhcHash, 
        Argon2Parameters targetParameters)
    {
        var result = RehashIfNeeded(password, currentPhcHash, targetParameters);
        return (result.Success, result.WasRehashed ? result.NewPhcHash : null);
    }

    /// <inheritdoc />
    public async ValueTask<(bool IsValid, string? NewHash)> VerifyAndRehashAsync(
        string password, 
        string currentPhcHash, 
        Argon2Parameters targetParameters, 
        CancellationToken cancellationToken = default)
    {
        var result = await RehashIfNeededAsync(password, currentPhcHash, targetParameters, cancellationToken)
            .ConfigureAwait(false);
        return (result.Success, result.WasRehashed ? result.NewPhcHash : null);
    }

    #region Static convenience methods

    /// <summary>
    /// Checks if a PHC hash needs to be rehashed to meet default security requirements.
    /// </summary>
    /// <param name="phcHash">The PHC-formatted hash to check.</param>
    /// <returns>True if rehash is recommended.</returns>
    public static bool NeedsRehash(string phcHash)
    {
        var service = new Argon2RehashService();
        var result = service.CheckNeedsRehash(phcHash, Argon2Parameters.CreateDefault());
        return result.NeedsRehash;
    }

    /// <summary>
    /// Checks if a PHC hash needs to be rehashed to meet specified requirements.
    /// </summary>
    /// <param name="phcHash">The PHC-formatted hash to check.</param>
    /// <param name="minimumParameters">Minimum acceptable parameters.</param>
    /// <returns>Result indicating if rehash is needed and why.</returns>
    public static RehashCheckResult CheckRehash(string phcHash, Argon2Parameters minimumParameters)
    {
        var service = new Argon2RehashService();
        return service.CheckNeedsRehash(phcHash, minimumParameters);
    }

    #endregion
}
