using Argon2Sharp.Abstractions;
using Argon2Sharp.Core;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Argon2Sharp;

/// <summary>
/// Extended Argon2 hasher with async support and progress reporting.
/// Implements <see cref="IArgon2AsyncHasher"/> for full async capabilities.
/// </summary>
/// <remarks>
/// <para>This class extends the base <see cref="Argon2"/> functionality with async operations
/// suitable for web applications and long-running processes.</para>
/// <para>All async methods support cancellation via <see cref="CancellationToken"/>.</para>
/// </remarks>
/// <example>
/// <code>
/// var hasher = new Argon2AsyncHasher(Argon2Parameters.CreateDefault());
/// 
/// // Async hashing
/// byte[] hash = await hasher.HashAsync("password");
/// 
/// // Async verification
/// bool isValid = await hasher.VerifyAsync("password", hash);
/// 
/// // With progress reporting
/// var progress = new Progress&lt;double&gt;(p => Console.WriteLine($"{p:P0}"));
/// hash = await hasher.HashAsync("password", progress);
/// </code>
/// </example>
public sealed class Argon2AsyncHasher : IArgon2AsyncHasher
{
    private readonly Argon2Parameters _parameters;

    /// <summary>
    /// Gets the parameters used by this hasher instance.
    /// </summary>
    public Argon2Parameters Parameters => _parameters;

    /// <summary>
    /// Creates an async Argon2 hasher with specified parameters.
    /// </summary>
    /// <param name="parameters">Argon2 parameters to use for hashing.</param>
    /// <exception cref="ArgumentNullException">Thrown when parameters is null.</exception>
    public Argon2AsyncHasher(Argon2Parameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    #region Synchronous IArgon2Hasher implementation

    /// <inheritdoc />
    public byte[] Hash(ReadOnlySpan<byte> password)
    {
        byte[] output = new byte[_parameters.HashLength];
        Hash(password, output);
        return output;
    }

    /// <inheritdoc />
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
    {
        if (output.Length != _parameters.HashLength)
        {
            throw new ArgumentException($"Output buffer must be {_parameters.HashLength} bytes", nameof(output));
        }

        var engine = new Argon2Engine(_parameters);
        engine.Hash(password, output);
    }

    /// <inheritdoc />
    public byte[] Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Hash(Encoding.UTF8.GetBytes(password).AsSpan());
    }

    /// <inheritdoc />
    public bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<byte> hash)
    {
        if (hash.Length != _parameters.HashLength)
        {
            return false;
        }

        Span<byte> computed = _parameters.HashLength <= 256 
            ? stackalloc byte[_parameters.HashLength] 
            : new byte[_parameters.HashLength];
        
        Hash(password, computed);
        return CryptographicOperations.FixedTimeEquals(computed, hash);
    }

    /// <inheritdoc />
    public bool Verify(string password, ReadOnlySpan<byte> hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Verify(Encoding.UTF8.GetBytes(password).AsSpan(), hash);
    }

    #endregion

    #region Asynchronous IArgon2AsyncHasher implementation

    /// <inheritdoc />
    public ValueTask<byte[]> HashAsync(ReadOnlyMemory<byte> password, CancellationToken cancellationToken = default)
    {
        return HashAsync(password, progress: null, cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<byte[]> HashAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return HashAsync(Encoding.UTF8.GetBytes(password).AsMemory(), progress: null, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> HashAsync(ReadOnlyMemory<byte> password, IProgress<double>? progress, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Offload CPU-intensive work to thread pool
        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            byte[] output = new byte[_parameters.HashLength];
            
            if (progress != null)
            {
                var engine = new Argon2Engine(_parameters);
                engine.HashWithProgress(password.Span, output, progress, cancellationToken);
            }
            else
            {
                var engine = new Argon2Engine(_parameters);
                engine.Hash(password.Span, output);
            }
            
            return output;
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> password, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default)
    {
        if (hash.Length != _parameters.HashLength)
        {
            return false;
        }

        cancellationToken.ThrowIfCancellationRequested();

        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            byte[] computed = new byte[_parameters.HashLength];
            var engine = new Argon2Engine(_parameters);
            engine.Hash(password.Span, computed);
            
            return CryptographicOperations.FixedTimeEquals(computed, hash.Span);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public ValueTask<bool> VerifyAsync(string password, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return VerifyAsync(Encoding.UTF8.GetBytes(password).AsMemory(), hash, cancellationToken);
    }

    #endregion

    #region Static async convenience methods

    /// <summary>
    /// Asynchronously hashes a password with default parameters and returns both hash and generated salt.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="parameters">Optional parameters (uses CreateDefault() if null).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A tuple containing the hash and the salt used.</returns>
    public static async ValueTask<(byte[] Hash, byte[] Salt)> HashPasswordWithSaltAsync(
        string password, 
        Argon2Parameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        var salt = Argon2.GenerateSalt(16);
        var p = (parameters ?? Argon2Parameters.CreateDefault()) with { Salt = salt };
        
        var hasher = new Argon2AsyncHasher(p);
        var hash = await hasher.HashAsync(password, cancellationToken).ConfigureAwait(false);
        
        return (hash, salt);
    }

    /// <summary>
    /// Asynchronously hashes a password to PHC format string.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="parameters">Optional parameters (uses CreateDefault() if null).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>PHC-formatted hash string.</returns>
    public static async ValueTask<string> HashToPhcStringAsync(
        string password,
        Argon2Parameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        var salt = Argon2.GenerateSalt(16);
        var p = (parameters ?? Argon2Parameters.CreateDefault()) with { Salt = salt };
        
        var hasher = new Argon2AsyncHasher(p);
        var hash = await hasher.HashAsync(password, cancellationToken).ConfigureAwait(false);
        
        return Argon2PhcFormat.Encode(hash, p);
    }

    /// <summary>
    /// Asynchronously verifies a password against a PHC-formatted hash string.
    /// </summary>
    /// <param name="password">Password to verify.</param>
    /// <param name="phcHash">PHC-formatted hash string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Tuple of (isValid, parameters extracted from hash).</returns>
    public static async ValueTask<(bool IsValid, Argon2Parameters? Parameters)> VerifyPhcStringAsync(
        string password,
        string phcHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(phcHash);

        if (!Argon2PhcFormat.TryDecode(phcHash, out var hash, out var parameters))
        {
            return (false, null);
        }

        var hasher = new Argon2AsyncHasher(parameters!);
        var isValid = await hasher.VerifyAsync(password, hash!.AsMemory(), cancellationToken).ConfigureAwait(false);
        
        return (isValid, parameters);
    }

    #endregion
}
