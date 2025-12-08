using Argon2Sharp.Abstractions;
using System.Diagnostics;

namespace Argon2Sharp;

/// <summary>
/// Automatic parameter tuner for Argon2 that finds optimal parameters
/// based on target execution time.
/// </summary>
/// <remarks>
/// <para>This class helps calibrate Argon2 parameters for specific hardware
/// by iteratively testing configurations to achieve a target hash time.</para>
/// <para>Useful for:</para>
/// <list type="bullet">
/// <item>Initial deployment configuration</item>
/// <item>Security audits to verify appropriate work factors</item>
/// <item>Adapting parameters as hardware capabilities change</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// var tuner = new Argon2ParameterTuner();
/// 
/// // Find parameters for ~500ms hash time
/// var params = tuner.TuneParameters(TimeSpan.FromMilliseconds(500));
/// 
/// // Find high-security parameters (~2 seconds)
/// var secureParams = tuner.TuneParameters(
///     targetTime: TimeSpan.FromSeconds(2),
///     maxMemoryMB: 256,
///     parallelism: 4);
/// </code>
/// </example>
public sealed class Argon2ParameterTuner : IArgon2ParameterTuner
{
    private const string TestPassword = "benchmark-password-for-tuning";
    private const int MinMemoryKB = 1024;      // 1 MB minimum
    private const int MaxMemoryKB = 4194304;   // 4 GB maximum
    private const int MinIterations = 1;
    private const int MaxIterations = 100;

    /// <inheritdoc />
    public Argon2Parameters TuneParameters(
        TimeSpan targetTime,
        int maxMemoryMB = 64,
        int parallelism = 1,
        Argon2Type type = Argon2Type.Argon2id)
    {
        ValidateInputs(targetTime, maxMemoryMB, parallelism);

        int maxMemoryKB = Math.Min(maxMemoryMB * 1024, MaxMemoryKB);
        
        // Start with minimum viable parameters
        int iterations = MinIterations;
        
        var salt = Argon2.GenerateSalt(16);
        
        // Phase 1: Find maximum memory that fits within target time with 1 iteration
        memoryKB = FindOptimalMemory(targetTime, maxMemoryKB, parallelism, type, salt);
        
        // Phase 2: Increase iterations to fill remaining time budget
        iterations = FindOptimalIterations(targetTime, memoryKB, parallelism, type, salt);
        
        return Argon2Parameters.CreateBuilder()
            .WithType(type)
            .WithMemorySizeKB(memoryKB)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();
    }

    /// <inheritdoc />
    public async ValueTask<Argon2Parameters> TuneParametersAsync(
        TimeSpan targetTime,
        int maxMemoryMB = 64,
        int parallelism = 1,
        Argon2Type type = Argon2Type.Argon2id,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => 
            TuneParameters(targetTime, maxMemoryMB, parallelism, type), 
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public TimeSpan EstimateHashTime(Argon2Parameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        
        var testParams = parameters with { Salt = Argon2.GenerateSalt(16) };
        return MeasureHashTime(testParams);
    }

    /// <inheritdoc />
    public async ValueTask<TimeSpan> EstimateHashTimeAsync(
        Argon2Parameters parameters,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => EstimateHashTime(parameters), cancellationToken).ConfigureAwait(false);
    }

    #region Extended API

    /// <summary>
    /// Gets a report of the current system's hashing capabilities.
    /// </summary>
    /// <param name="parallelism">Degree of parallelism to test.</param>
    /// <returns>A capability report.</returns>
    public SystemCapabilityReport GetSystemCapabilities(int parallelism = 1)
    {
        var salt = Argon2.GenerateSalt(16);
        var results = new List<(int MemoryMB, int Iterations, TimeSpan Time)>();
        
        // Test various configurations
        int[] memoryTestsMB = [1, 4, 16, 64, 128, 256];
        int[] iterationTests = [1, 2, 4];
        
        foreach (var memMB in memoryTestsMB)
        {
            foreach (var iters in iterationTests)
            {
                try
                {
                    var testParams = Argon2Parameters.CreateBuilder()
                        .WithMemorySizeKB(memMB * 1024)
                        .WithIterations(iters)
                        .WithParallelism(parallelism)
                        .WithSalt(salt)
                        .Build();
                    
                    var time = MeasureHashTime(testParams);
                    results.Add((memMB, iters, time));
                }
                catch (OutOfMemoryException)
                {
                    // Skip configurations that exceed available memory
                    break;
                }
            }
        }
        
        return new SystemCapabilityReport(
            ProcessorCount: Environment.ProcessorCount,
            TestedParallelism: parallelism,
            Benchmarks: results.ToArray());
    }

    /// <summary>
    /// Suggests parameters based on use case presets.
    /// </summary>
    /// <param name="useCase">The intended use case.</param>
    /// <returns>Recommended parameters for the use case.</returns>
    public Argon2Parameters SuggestParameters(Argon2UseCase useCase)
    {
        return useCase switch
        {
            Argon2UseCase.WebApplication => TuneParameters(
                TimeSpan.FromMilliseconds(300), 
                maxMemoryMB: 64, 
                parallelism: 1),
                
            Argon2UseCase.MobileApplication => TuneParameters(
                TimeSpan.FromMilliseconds(500), 
                maxMemoryMB: 32, 
                parallelism: 1),
                
            Argon2UseCase.DesktopApplication => TuneParameters(
                TimeSpan.FromSeconds(1), 
                maxMemoryMB: 256, 
                parallelism: Math.Max(1, Environment.ProcessorCount / 2)),
                
            Argon2UseCase.BackgroundService => TuneParameters(
                TimeSpan.FromSeconds(3), 
                maxMemoryMB: 512, 
                parallelism: Environment.ProcessorCount),
                
            Argon2UseCase.HighSecurity => TuneParameters(
                TimeSpan.FromSeconds(5), 
                maxMemoryMB: 1024, 
                parallelism: Environment.ProcessorCount),
                
            _ => throw new ArgumentOutOfRangeException(nameof(useCase))
        };
    }

    #endregion

    #region Private helpers

    private int FindOptimalMemory(TimeSpan targetTime, int maxMemoryKB, int parallelism, Argon2Type type, byte[] salt)
    {
        int low = Math.Max(MinMemoryKB, 8 * parallelism);
        int high = maxMemoryKB;
        int optimal = low;
        
        // Binary search for optimal memory
        while (low <= high)
        {
            int mid = low + (high - low) / 2;
            // Round to nearest multiple of 8*parallelism (memory constraint)
            mid = (mid / (8 * parallelism)) * (8 * parallelism);
            if (mid < low)
            {
                mid = low;
            }
            
            var testParams = Argon2Parameters.CreateBuilder()
                .WithType(type)
                .WithMemorySizeKB(mid)
                .WithIterations(1)
                .WithParallelism(parallelism)
                .WithSalt(salt)
                .Build();
            
            var elapsed = MeasureHashTime(testParams);
            
            if (elapsed <= targetTime)
            {
                optimal = mid;
                low = mid + (8 * parallelism);
            }
            else
            {
                high = mid - (8 * parallelism);
            }
        }
        
        return optimal;
    }

    private int FindOptimalIterations(TimeSpan targetTime, int memoryKB, int parallelism, Argon2Type type, byte[] salt)
    {
        int iterations = MinIterations;
        TimeSpan elapsed;
        
        // Measure with 1 iteration
        var testParams = Argon2Parameters.CreateBuilder()
            .WithType(type)
            .WithMemorySizeKB(memoryKB)
            .WithIterations(1)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();
        
        var baseTime = MeasureHashTime(testParams);
        
        if (baseTime >= targetTime)
        {
            return 1;
        }
        
        // Estimate iterations needed
        double timePerIteration = baseTime.TotalMilliseconds;
        int estimatedIterations = Math.Max(1, (int)(targetTime.TotalMilliseconds / timePerIteration));
        estimatedIterations = Math.Min(estimatedIterations, MaxIterations);
        
        // Fine-tune: find the iteration count that gets closest to the target time
        int bestIterations = estimatedIterations;
        double bestDiff = double.MaxValue;
        for (iterations = estimatedIterations; iterations <= MaxIterations; iterations++)
        {
            testParams = testParams with { Iterations = iterations };
            elapsed = MeasureHashTime(testParams);

            double diff = Math.Abs(elapsed.TotalMilliseconds - targetTime.TotalMilliseconds);
            if (diff < bestDiff)
            {
                bestIterations = iterations;
                bestDiff = diff;
            }

            if (elapsed.TotalMilliseconds > targetTime.TotalMilliseconds * 1.1) // Stop if we exceed target by 10%
            {
                break;
            }
        }

        return Math.Min(bestIterations, MaxIterations);
    }

    private static TimeSpan MeasureHashTime(Argon2Parameters parameters)
    {
        var argon2 = new Argon2(parameters);
        byte[] output = new byte[parameters.HashLength];
        
        // Warm-up run
        argon2.Hash(TestPassword, output);
        
        // Timed run
        var sw = Stopwatch.StartNew();
        argon2.Hash(TestPassword, output);
        sw.Stop();
        
        return sw.Elapsed;
    }

    private static void ValidateInputs(TimeSpan targetTime, int maxMemoryMB, int parallelism)
    {
        if (targetTime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(targetTime), "Target time must be positive");
        }
        
        if (targetTime > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(targetTime), "Target time should not exceed 5 minutes");
        }
        
        if (maxMemoryMB < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxMemoryMB), "Maximum memory must be at least 1 MB");
        }
        
        if (parallelism < 1 || parallelism > 255)
        {
            throw new ArgumentOutOfRangeException(nameof(parallelism), "Parallelism must be between 1 and 255");
        }
    }

    #endregion
}

/// <summary>
/// Common use cases for Argon2 parameter suggestions.
/// </summary>
public enum Argon2UseCase
{
    /// <summary>Web application with response time requirements (~300ms).</summary>
    WebApplication,
    
    /// <summary>Mobile application with battery/memory constraints (~500ms).</summary>
    MobileApplication,
    
    /// <summary>Desktop application with more available resources (~1s).</summary>
    DesktopApplication,
    
    /// <summary>Background service with no immediate user interaction (~3s).</summary>
    BackgroundService,
    
    /// <summary>High security requirements (file encryption, key derivation) (~5s).</summary>
    HighSecurity
}

/// <summary>
/// Report of system hashing capabilities.
/// </summary>
/// <param name="ProcessorCount">Number of logical processors.</param>
/// <param name="TestedParallelism">Parallelism level tested.</param>
/// <param name="Benchmarks">Array of benchmark results.</param>
public readonly record struct SystemCapabilityReport(
    int ProcessorCount,
    int TestedParallelism,
    (int MemoryMB, int Iterations, TimeSpan Time)[] Benchmarks)
{
    /// <summary>
    /// Gets the fastest configuration tested.
    /// </summary>
    public (int MemoryMB, int Iterations, TimeSpan Time)? FastestConfiguration =>
        Benchmarks.Length > 0 ? Benchmarks.MinBy(b => b.Time) : null;
    
    /// <summary>
    /// Gets the most secure configuration tested within a time budget.
    /// </summary>
    /// <param name="maxTime">Maximum acceptable time.</param>
    /// <returns>The most secure configuration within the time budget.</returns>
    public (int MemoryMB, int Iterations, TimeSpan Time)? MostSecureWithin(TimeSpan maxTime) =>
        Benchmarks
            .Where(b => b.Time <= maxTime)
            .OrderByDescending(b => b.MemoryMB * b.Iterations)
            .FirstOrDefault();
}
