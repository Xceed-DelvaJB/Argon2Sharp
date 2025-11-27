namespace Argon2Sharp.Abstractions;

/// <summary>
/// Progress information for a single hash operation.
/// </summary>
/// <param name="Phase">Current phase of the operation.</param>
/// <param name="CurrentPass">Current pass number (1-based).</param>
/// <param name="TotalPasses">Total number of passes.</param>
/// <param name="CurrentSlice">Current slice number (0-3).</param>
/// <param name="PercentComplete">Overall completion percentage (0-100).</param>
public readonly record struct HashProgress(
    HashPhase Phase,
    int CurrentPass,
    int TotalPasses,
    int CurrentSlice,
    double PercentComplete);

/// <summary>
/// Phases of the Argon2 hashing operation.
/// </summary>
public enum HashPhase
{
    /// <summary>Initializing memory and parameters.</summary>
    Initializing = 0,
    
    /// <summary>Filling memory blocks.</summary>
    FillingMemory = 1,
    
    /// <summary>Finalizing hash output.</summary>
    Finalizing = 2,
    
    /// <summary>Operation completed.</summary>
    Completed = 3
}

/// <summary>
/// Extended hasher interface with progress reporting support.
/// </summary>
public interface IArgon2ProgressHasher : IArgon2Hasher
{
    /// <summary>
    /// Computes Argon2 hash with progress reporting.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <param name="progress">Progress reporter.</param>
    /// <returns>Hash bytes.</returns>
    byte[] Hash(ReadOnlySpan<byte> password, IProgress<HashProgress>? progress);

    /// <summary>
    /// Computes Argon2 hash with progress reporting.
    /// </summary>
    /// <param name="password">Password string to hash.</param>
    /// <param name="progress">Progress reporter.</param>
    /// <returns>Hash bytes.</returns>
    byte[] Hash(string password, IProgress<HashProgress>? progress);

    /// <summary>
    /// Asynchronously computes Argon2 hash with progress reporting.
    /// </summary>
    /// <param name="password">Password bytes to hash.</param>
    /// <param name="progress">Progress reporter.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Hash bytes.</returns>
    ValueTask<byte[]> HashAsync(ReadOnlyMemory<byte> password, IProgress<HashProgress>? progress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously computes Argon2 hash with progress reporting.
    /// </summary>
    /// <param name="password">Password string to hash.</param>
    /// <param name="progress">Progress reporter.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Hash bytes.</returns>
    ValueTask<byte[]> HashAsync(string password, IProgress<HashProgress>? progress, CancellationToken cancellationToken = default);
}
