using Argon2Sharp.Abstractions;
using Argon2Sharp.Core;
using System.Security.Cryptography;
using System.Text;

namespace Argon2Sharp;

/// <summary>
/// Argon2-based Key Derivation Function (KDF) implementation.
/// Derives cryptographic keys from passwords using the Argon2 algorithm.
/// </summary>
/// <remarks>
/// <para>This class implements <see cref="IArgon2KeyDerivation"/> for deriving keys
/// suitable for encryption, HMAC, or other cryptographic operations.</para>
/// <para>Uses Argon2id by default, which provides resistance against both 
/// side-channel and GPU-based attacks.</para>
/// </remarks>
/// <example>
/// <code>
/// var kdf = new Argon2KeyDerivation();
/// 
/// // Derive a 256-bit key for AES encryption
/// byte[] salt = Argon2.GenerateSalt(16);
/// byte[] key = kdf.DeriveKey("masterPassword", salt, 32);
/// 
/// // Derive multiple keys from the same password
/// byte[] encryptionKey = kdf.DeriveKey("password", salt, 32);
/// byte[] macKey = kdf.DeriveKey("password", salt, 64);
/// </code>
/// </example>
public sealed class Argon2KeyDerivation : IArgon2KeyDerivation
{
    private readonly Argon2Parameters _defaultParameters;

    /// <summary>
    /// Creates a new KDF instance with default parameters suitable for key derivation.
    /// </summary>
    /// <remarks>
    /// Default parameters are more aggressive than password hashing defaults
    /// to provide stronger key derivation security.
    /// </remarks>
    public Argon2KeyDerivation() : this(CreateKdfDefaultParameters())
    {
    }

    /// <summary>
    /// Creates a new KDF instance with custom base parameters.
    /// </summary>
    /// <param name="baseParameters">Base parameters to use (salt and hash length will be overridden per operation).</param>
    public Argon2KeyDerivation(Argon2Parameters baseParameters)
    {
        _defaultParameters = baseParameters ?? throw new ArgumentNullException(nameof(baseParameters));
    }

    /// <summary>
    /// Creates default parameters optimized for key derivation.
    /// </summary>
    /// <returns>Parameters suitable for KDF operations.</returns>
    public static Argon2Parameters CreateKdfDefaultParameters()
    {
        return Argon2Parameters.CreateBuilder()
            .WithType(Argon2Type.Argon2id)
            .WithMemorySizeKB(65536)  // 64 MB - more memory for KDF
            .WithIterations(3)
            .WithParallelism(1)
            .WithHashLength(32)
            .Build();
    }

    /// <inheritdoc />
    public byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int keyLength)
    {
        ValidateInputs(salt, keyLength);
        
        byte[] output = new byte[keyLength];
        DeriveKey(password, salt, output);
        return output;
    }

    /// <inheritdoc />
    public void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> output)
    {
        ValidateInputs(salt, output.Length);
        
        var parameters = _defaultParameters with 
        { 
            Salt = salt.ToArray(),
            HashLength = output.Length
        };
        
        var engine = new Argon2Engine(parameters);
        engine.Hash(password, output);
    }

    /// <inheritdoc />
    public byte[] DeriveKey(string password, ReadOnlySpan<byte> salt, int keyLength)
    {
        ArgumentNullException.ThrowIfNull(password);
        return DeriveKey(Encoding.UTF8.GetBytes(password).AsSpan(), salt, keyLength);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> DeriveKeyAsync(ReadOnlyMemory<byte> password, ReadOnlyMemory<byte> salt, int keyLength, CancellationToken cancellationToken = default)
    {
        ValidateInputs(salt.Span, keyLength);
        
        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return DeriveKey(password.Span, salt.Span, keyLength);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> DeriveKeyAsync(string password, ReadOnlyMemory<byte> salt, int keyLength, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return await DeriveKeyAsync(Encoding.UTF8.GetBytes(password).AsMemory(), salt, keyLength, cancellationToken).ConfigureAwait(false);
    }

    #region Extended API

    /// <summary>
    /// Derives a key using specified parameters, overriding defaults.
    /// </summary>
    /// <param name="password">Password to derive key from.</param>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="keyLength">Desired key length.</param>
    /// <param name="parameters">Custom parameters (salt and hash length will be set from other arguments).</param>
    /// <returns>Derived key bytes.</returns>
    public byte[] DeriveKey(string password, byte[] salt, int keyLength, Argon2Parameters parameters)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(parameters);
        ValidateInputs(salt, keyLength);

        var actualParams = parameters with 
        { 
            Salt = salt,
            HashLength = keyLength
        };
        
        var engine = new Argon2Engine(actualParams);
        byte[] output = new byte[keyLength];
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            engine.Hash(passwordBytes.AsSpan(), output);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>
    /// Derives multiple keys from the same password using domain separation.
    /// </summary>
    /// <param name="password">Master password.</param>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="keyLengths">Array of key lengths to derive.</param>
    /// <param name="contexts">Optional context strings for domain separation.</param>
    /// <returns>Array of derived keys.</returns>
    public byte[][] DeriveKeys(string password, byte[] salt, int[] keyLengths, string[]? contexts = null)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(keyLengths);
        
        if (keyLengths.Length == 0)
        {
            throw new ArgumentException("At least one key length must be specified", nameof(keyLengths));
        }

        if (contexts != null && contexts.Length != keyLengths.Length)
        {
            throw new ArgumentException("Contexts array must match key lengths array", nameof(contexts));
        }

        var keys = new byte[keyLengths.Length][];
        
        for (int i = 0; i < keyLengths.Length; i++)
        {
            byte[] contextSalt;
            if (contexts != null)
            {
                // Combine salt with context for domain separation
                var contextBytes = Encoding.UTF8.GetBytes(contexts[i]);
                contextSalt = new byte[salt.Length + contextBytes.Length];
                salt.CopyTo(contextSalt, 0);
                contextBytes.CopyTo(contextSalt, salt.Length);
            }
            else
            {
                // Use index for basic domain separation
                contextSalt = new byte[salt.Length + 4];
                salt.CopyTo(contextSalt, 0);
                BitConverter.GetBytes(i).CopyTo(contextSalt, salt.Length);
            }
            
            keys[i] = DeriveKey(password, contextSalt, keyLengths[i]);
        }
        
        return keys;
    }

    /// <summary>
    /// Derives a key and immediately secures it in a buffer that will be zeroed on disposal.
    /// </summary>
    /// <param name="password">Password to derive key from.</param>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="keyLength">Desired key length.</param>
    /// <returns>A disposable secure key that zeros memory when disposed.</returns>
    public SecureKeyBuffer DeriveSecureKey(string password, byte[] salt, int keyLength)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        
        byte[] key = DeriveKey(password, salt, keyLength);
        return new SecureKeyBuffer(key);
    }

    #endregion

    #region Validation

    private static void ValidateInputs(ReadOnlySpan<byte> salt, int keyLength)
    {
        if (salt.Length < 8)
        {
            throw new ArgumentException("Salt must be at least 8 bytes", nameof(salt));
        }
        
        if (keyLength < 4)
        {
            throw new ArgumentException("Key length must be at least 4 bytes", nameof(keyLength));
        }
        
        // Removed artificial upper limit on key length.
        // Argon2 supports output lengths up to 2^32 - 1 bytes (RFC 9106).
        // If needed, enforce limits based on system resources or make configurable.
    }
    #endregion
}

/// <summary>
/// A secure buffer that automatically zeros its contents when disposed.
/// </summary>
public sealed class SecureKeyBuffer : IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;

    internal SecureKeyBuffer(byte[] key)
    {
        _key = key;
    }

    /// <summary>
    /// Gets a read-only span of the key bytes.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the buffer has been disposed.</exception>
    public ReadOnlySpan<byte> Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    /// <summary>
    /// Gets the length of the key in bytes.
    /// </summary>
    public int Length => _key.Length;

    /// <summary>
    /// Copies the key to the destination span.
    /// </summary>
    /// <param name="destination">Destination buffer.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the buffer has been disposed.</exception>
    public void CopyTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _key.CopyTo(destination);
    }

    /// <summary>
    /// Disposes the buffer and zeros the key memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_key);
            _disposed = true;
        }
    }
}
