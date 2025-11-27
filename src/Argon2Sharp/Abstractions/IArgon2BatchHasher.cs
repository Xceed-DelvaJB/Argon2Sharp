namespace Argon2Sharp.Abstractions;

/// <summary>
/// Result of a batch hash operation.
/// </summary>
/// <param name="Index">The index of the password in the batch.</param>
/// <param name="Password">The original password (if included).</param>
/// <param name="Hash">The computed hash bytes.</param>
/// <param name="Salt">The salt used for hashing.</param>
/// <param name="PhcHash">The PHC-formatted hash string.</param>
/// <param name="Success">Whether the operation succeeded.</param>
/// <param name="Error">Error message if failed.</param>
public readonly record struct BatchHashResult(
    int Index,
    string? Password,
    byte[]? Hash,
    byte[]? Salt,
    string? PhcHash,
    bool Success,
    string? Error = null);

/// <summary>
/// Options for batch hashing operations.
/// </summary>
public sealed class BatchHashOptions
{
    /// <summary>
    /// Maximum degree of parallelism for batch processing.
    /// Default: Environment.ProcessorCount
    /// </summary>
    public int MaxDegreeOfParallelism { get; init; } = Environment.ProcessorCount;

    /// <summary>
    /// Whether to include the original password in the result.
    /// Default: false (for security)
    /// </summary>
    public bool IncludePasswordInResult { get; init; } = false;

    /// <summary>
    /// Whether to generate PHC format strings.
    /// Default: true
    /// </summary>
    public bool GeneratePhcStrings { get; init; } = true;

    /// <summary>
    /// Whether to continue processing on errors.
    /// Default: true
    /// </summary>
    public bool ContinueOnError { get; init; } = true;

    /// <summary>
    /// Delay between batches to prevent resource exhaustion.
    /// Default: TimeSpan.Zero (no delay)
    /// </summary>
    public TimeSpan BatchDelay { get; init; } = TimeSpan.Zero;
}

/// <summary>
/// Defines the contract for batch password hashing operations.
/// </summary>
public interface IArgon2BatchHasher
{
    /// <summary>
    /// Hashes a batch of passwords asynchronously, yielding results as they complete.
    /// </summary>
    /// <param name="passwords">The passwords to hash.</param>
    /// <param name="parameters">The Argon2 parameters (salt will be auto-generated for each).</param>
    /// <param name="options">Batch processing options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of hash results.</returns>
    IAsyncEnumerable<BatchHashResult> HashBatchAsync(
        IEnumerable<string> passwords,
        Argon2Parameters parameters,
        BatchHashOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Hashes a batch of passwords asynchronously with progress reporting.
    /// </summary>
    /// <param name="passwords">The passwords to hash.</param>
    /// <param name="parameters">The Argon2 parameters.</param>
    /// <param name="progress">Progress reporter.</param>
    /// <param name="options">Batch processing options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of hash results.</returns>
    IAsyncEnumerable<BatchHashResult> HashBatchAsync(
        IEnumerable<string> passwords,
        Argon2Parameters parameters,
        IProgress<BatchProgress>? progress,
        BatchHashOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a batch of password-hash pairs asynchronously.
    /// </summary>
    /// <param name="passwordHashPairs">Pairs of (password, phcHash) to verify.</param>
    /// <param name="options">Batch processing options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of verification results.</returns>
    IAsyncEnumerable<BatchVerifyResult> VerifyBatchAsync(
        IEnumerable<(string Password, string PhcHash)> passwordHashPairs,
        BatchHashOptions? options = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Progress information for batch operations.
/// </summary>
/// <param name="Completed">Number of completed operations.</param>
/// <param name="Total">Total number of operations.</param>
/// <param name="SuccessCount">Number of successful operations.</param>
/// <param name="FailureCount">Number of failed operations.</param>
/// <param name="ElapsedTime">Elapsed time since start.</param>
/// <param name="EstimatedTimeRemaining">Estimated time remaining.</param>
public readonly record struct BatchProgress(
    int Completed,
    int Total,
    int SuccessCount,
    int FailureCount,
    TimeSpan ElapsedTime,
    TimeSpan? EstimatedTimeRemaining)
{
    /// <summary>
    /// Gets the completion percentage (0-100).
    /// </summary>
    public double PercentComplete => Total > 0 ? (double)Completed / Total * 100 : 0;
}

/// <summary>
/// Result of a batch verify operation.
/// </summary>
/// <param name="Index">The index in the batch.</param>
/// <param name="IsValid">Whether the password matches the hash.</param>
/// <param name="Success">Whether the operation completed successfully.</param>
/// <param name="Error">Error message if failed.</param>
public readonly record struct BatchVerifyResult(
    int Index,
    bool IsValid,
    bool Success,
    string? Error = null);
