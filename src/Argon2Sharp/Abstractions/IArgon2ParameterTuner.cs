namespace Argon2Sharp.Abstractions;

/// <summary>
/// Defines the contract for automatic parameter tuning based on target execution time.
/// </summary>
public interface IArgon2ParameterTuner
{
    /// <summary>
    /// Tunes Argon2 parameters to achieve a target hashing time.
    /// </summary>
    /// <param name="targetTime">Target time for a single hash operation.</param>
    /// <param name="maxMemoryMB">Maximum memory to use in megabytes (default: 64 MB).</param>
    /// <param name="parallelism">Degree of parallelism (default: 1).</param>
    /// <param name="type">Argon2 type (default: Argon2id).</param>
    /// <returns>Tuned parameters that achieve approximately the target time.</returns>
    Argon2Parameters TuneParameters(TimeSpan targetTime, int maxMemoryMB = 64, int parallelism = 1, Argon2Type type = Argon2Type.Argon2id);

    /// <summary>
    /// Asynchronously tunes Argon2 parameters to achieve a target hashing time.
    /// </summary>
    /// <param name="targetTime">Target time for a single hash operation.</param>
    /// <param name="maxMemoryMB">Maximum memory to use in megabytes.</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="type">Argon2 type.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Tuned parameters that achieve approximately the target time.</returns>
    ValueTask<Argon2Parameters> TuneParametersAsync(TimeSpan targetTime, int maxMemoryMB = 64, int parallelism = 1, Argon2Type type = Argon2Type.Argon2id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Estimates the time required to hash with given parameters.
    /// </summary>
    /// <param name="parameters">Parameters to estimate.</param>
    /// <returns>Estimated hashing time.</returns>
    TimeSpan EstimateHashTime(Argon2Parameters parameters);

    /// <summary>
    /// Asynchronously estimates the time required to hash with given parameters.
    /// </summary>
    /// <param name="parameters">Parameters to estimate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Estimated hashing time.</returns>
    ValueTask<TimeSpan> EstimateHashTimeAsync(Argon2Parameters parameters, CancellationToken cancellationToken = default);
}
