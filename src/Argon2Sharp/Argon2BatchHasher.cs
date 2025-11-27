using Argon2Sharp.Abstractions;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace Argon2Sharp;

/// <summary>
/// High-performance batch password hasher with async enumerable support.
/// </summary>
/// <remarks>
/// <para>This class implements <see cref="IArgon2BatchHasher"/> for efficiently
/// hashing large batches of passwords, such as during database migrations.</para>
/// <para>Features:</para>
/// <list type="bullet">
/// <item>Parallel processing with configurable concurrency</item>
/// <item>Progress reporting for monitoring</item>
/// <item>Results streamed via IAsyncEnumerable</item>
/// <item>Memory-efficient processing</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// var batchHasher = new Argon2BatchHasher();
/// var parameters = Argon2Parameters.CreateDefault();
/// 
/// var passwords = new[] { "pass1", "pass2", "pass3" };
/// 
/// await foreach (var result in batchHasher.HashBatchAsync(passwords, parameters))
/// {
///     if (result.Success)
///     {
///         Console.WriteLine($"Password {result.Index}: {result.PhcHash}");
///     }
/// }
/// </code>
/// </example>
public sealed class Argon2BatchHasher : IArgon2BatchHasher
{
    /// <inheritdoc />
    public IAsyncEnumerable<BatchHashResult> HashBatchAsync(
        IEnumerable<string> passwords,
        Argon2Parameters parameters,
        BatchHashOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return HashBatchAsync(passwords, parameters, progress: null, options, cancellationToken);
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<BatchHashResult> HashBatchAsync(
        IEnumerable<string> passwords,
        Argon2Parameters parameters,
        IProgress<BatchProgress>? progress,
        BatchHashOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(passwords);
        ArgumentNullException.ThrowIfNull(parameters);

        options ??= new BatchHashOptions();
        
        var passwordList = passwords.ToList();
        int total = passwordList.Count;
        int completed = 0;
        int successCount = 0;
        int failureCount = 0;
        var stopwatch = Stopwatch.StartNew();

        // Create a bounded channel for results
        var channel = Channel.CreateBounded<BatchHashResult>(new BoundedChannelOptions(options.MaxDegreeOfParallelism * 2)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

        // Start producer task
        var producerTask = Task.Run(async () =>
        {
            try
            {
                await Parallel.ForEachAsync(
                    passwordList.Select((p, i) => (Password: p, Index: i)),
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = options.MaxDegreeOfParallelism,
                        CancellationToken = cancellationToken
                    },
                    async (item, ct) =>
                    {
                        BatchHashResult result;
                        
                        try
                        {
                            ct.ThrowIfCancellationRequested();
                            
                            var salt = Argon2.GenerateSalt(16);
                            var hashParams = parameters with { Salt = salt };
                            
                            var hasher = new Argon2AsyncHasher(hashParams);
                            var hash = await hasher.HashAsync(item.Password, ct).ConfigureAwait(false);
                            
                            string? phcHash = null;
                            if (options.GeneratePhcStrings)
                            {
                                phcHash = Argon2PhcFormat.Encode(hash, hashParams);
                            }
                            
                            result = new BatchHashResult(
                                Index: item.Index,
                                Password: options.IncludePasswordInResult ? item.Password : null,
                                Hash: hash,
                                Salt: salt,
                                PhcHash: phcHash,
                                Success: true);
                            
                            Interlocked.Increment(ref successCount);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            if (!options.ContinueOnError)
                            {
                                throw;
                            }
                            
                            result = new BatchHashResult(
                                Index: item.Index,
                                Password: options.IncludePasswordInResult ? item.Password : null,
                                Hash: null,
                                Salt: null,
                                PhcHash: null,
                                Success: false,
                                Error: ex.Message);
                            
                            Interlocked.Increment(ref failureCount);
                        }
                        
                        await channel.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                        
                        var currentCompleted = Interlocked.Increment(ref completed);
                        
                        if (progress != null)
                        {
                            var elapsed = stopwatch.Elapsed;
                            TimeSpan? remaining = currentCompleted > 0 
                                ? TimeSpan.FromTicks(elapsed.Ticks * (total - currentCompleted) / currentCompleted)
                                : null;
                            
                            progress.Report(new BatchProgress(
                                Completed: currentCompleted,
                                Total: total,
                                SuccessCount: Volatile.Read(ref successCount),
                                FailureCount: Volatile.Read(ref failureCount),
                                ElapsedTime: elapsed,
                                EstimatedTimeRemaining: remaining));
                        }
                        
                        if (options.BatchDelay > TimeSpan.Zero)
                        {
                            await Task.Delay(options.BatchDelay, ct).ConfigureAwait(false);
                        }
                    }).ConfigureAwait(false);
            }
            finally
            {
                channel.Writer.Complete();
            }
        }, cancellationToken);

        // Read results from channel
        await foreach (var result in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return result;
        }

        // Ensure producer completes
        await producerTask.ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<BatchVerifyResult> VerifyBatchAsync(
        IEnumerable<(string Password, string PhcHash)> passwordHashPairs,
        BatchHashOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(passwordHashPairs);

        options ??= new BatchHashOptions();
        
        var pairsList = passwordHashPairs.ToList();
        
        var channel = Channel.CreateBounded<BatchVerifyResult>(new BoundedChannelOptions(options.MaxDegreeOfParallelism * 2)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

        var producerTask = Task.Run(async () =>
        {
            try
            {
                await Parallel.ForEachAsync(
                    pairsList.Select((p, i) => (p.Password, p.PhcHash, Index: i)),
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = options.MaxDegreeOfParallelism,
                        CancellationToken = cancellationToken
                    },
                    async (item, ct) =>
                    {
                        BatchVerifyResult result;
                        
                        try
                        {
                            ct.ThrowIfCancellationRequested();
                            
                            var (isValid, _) = await Argon2AsyncHasher.VerifyPhcStringAsync(
                                item.Password, item.PhcHash, ct).ConfigureAwait(false);
                            
                            result = new BatchVerifyResult(
                                Index: item.Index,
                                IsValid: isValid,
                                Success: true);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            if (!options.ContinueOnError)
                            {
                                throw;
                            }
                            
                            result = new BatchVerifyResult(
                                Index: item.Index,
                                IsValid: false,
                                Success: false,
                                Error: ex.Message);
                        }
                        
                        await channel.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                    }).ConfigureAwait(false);
            }
            finally
            {
                channel.Writer.Complete();
            }
        }, cancellationToken);

        await foreach (var result in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return result;
        }

        await producerTask.ConfigureAwait(false);
    }

    #region Static convenience methods

    /// <summary>
    /// Hashes a batch of passwords and collects all results.
    /// </summary>
    /// <param name="passwords">Passwords to hash.</param>
    /// <param name="parameters">Argon2 parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Array of all hash results.</returns>
    public static async Task<BatchHashResult[]> HashAllAsync(
        IEnumerable<string> passwords,
        Argon2Parameters parameters,
        CancellationToken cancellationToken = default)
    {
        var batchHasher = new Argon2BatchHasher();
        var results = new List<BatchHashResult>();
        
        await foreach (var result in batchHasher.HashBatchAsync(passwords, parameters, cancellationToken: cancellationToken))
        {
            results.Add(result);
        }
        
        return results.OrderBy(r => r.Index).ToArray();
    }

    /// <summary>
    /// Verifies a batch of password-hash pairs and collects all results.
    /// </summary>
    /// <param name="passwordHashPairs">Password-hash pairs to verify.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Array of all verification results.</returns>
    public static async Task<BatchVerifyResult[]> VerifyAllAsync(
        IEnumerable<(string Password, string PhcHash)> passwordHashPairs,
        CancellationToken cancellationToken = default)
    {
        var batchHasher = new Argon2BatchHasher();
        var results = new List<BatchVerifyResult>();
        
        await foreach (var result in batchHasher.VerifyBatchAsync(passwordHashPairs, cancellationToken: cancellationToken))
        {
            results.Add(result);
        }
        
        return results.OrderBy(r => r.Index).ToArray();
    }

    #endregion
}
