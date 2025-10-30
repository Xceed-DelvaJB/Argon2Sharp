namespace Argon2Sharp;

/// <summary>
/// Parameters for Argon2 hash computation.
/// All parameters are validated according to RFC 9106 specifications.
/// </summary>
public sealed class Argon2Parameters
{
    private int _memorySizeKB;
    private int _iterations;
    private int _parallelism;
    private int _hashLength;

    /// <summary>
    /// Argon2 algorithm type (Argon2d, Argon2i, or Argon2id).
    /// Default: Argon2id (recommended by RFC 9106).
    /// </summary>
    public Argon2Type Type { get; set; } = Argon2Type.Argon2id;

    /// <summary>
    /// Argon2 version.
    /// Default: Version13 (current RFC 9106 version).
    /// </summary>
    public Argon2Version Version { get; set; } = Argon2Version.Version13;

    /// <summary>
    /// Memory size in kilobytes.
    /// Minimum: 8 * Parallelism KB.
    /// Recommended: at least 19 MB (19456 KB) for password hashing.
    /// </summary>
    public int MemorySizeKB
    {
        get => _memorySizeKB;
        set
        {
            if (value < 8)
                throw new ArgumentOutOfRangeException(nameof(value), "Memory size must be at least 8 KB");
            _memorySizeKB = value;
        }
    }

    /// <summary>
    /// Number of iterations (time cost).
    /// Minimum: 1.
    /// Recommended: at least 2 for password hashing.
    /// </summary>
    public int Iterations
    {
        get => _iterations;
        set
        {
            if (value < 1)
                throw new ArgumentOutOfRangeException(nameof(value), "Iterations must be at least 1");
            _iterations = value;
        }
    }

    /// <summary>
    /// Degree of parallelism (number of threads).
    /// Minimum: 1.
    /// Maximum: 2^24 - 1.
    /// Recommended: match number of CPU cores, typically 1-4 for password hashing.
    /// </summary>
    public int Parallelism
    {
        get => _parallelism;
        set
        {
            if (value < 1 || value > 0xFFFFFF)
                throw new ArgumentOutOfRangeException(nameof(value), "Parallelism must be between 1 and 16777215");
            _parallelism = value;
        }
    }

    /// <summary>
    /// Desired hash output length in bytes.
    /// Minimum: 4 bytes.
    /// Typical: 32 bytes (256 bits) or 64 bytes (512 bits).
    /// </summary>
    public int HashLength
    {
        get => _hashLength;
        set
        {
            if (value < 4)
                throw new ArgumentOutOfRangeException(nameof(value), "Hash length must be at least 4 bytes");
            _hashLength = value;
        }
    }

    /// <summary>
    /// Salt bytes (required).
    /// Minimum length: 8 bytes.
    /// Recommended: 16 bytes or more.
    /// Must be cryptographically random.
    /// </summary>
    public byte[]? Salt { get; set; }

    /// <summary>
    /// Optional secret/key for keyed hashing.
    /// Maximum length: 2^32 - 1 bytes.
    /// </summary>
    public byte[]? Secret { get; set; }

    /// <summary>
    /// Optional associated data (additional input).
    /// Maximum length: 2^32 - 1 bytes.
    /// </summary>
    public byte[]? AssociatedData { get; set; }

    /// <summary>
    /// Creates default parameters suitable for password hashing.
    /// Uses Argon2id with RFC 9106 recommended minimum parameters.
    /// </summary>
    public static Argon2Parameters CreateDefault()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 19456,      // 19 MB
            Iterations = 2,             // 2 passes
            Parallelism = 1,            // Single-threaded
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Creates high-security parameters for password hashing.
    /// Higher memory cost and iteration count.
    /// </summary>
    public static Argon2Parameters CreateHighSecurity()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 65536,      // 64 MB
            Iterations = 4,             // 4 passes
            Parallelism = 4,            // 4 threads
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Creates parameters suitable for testing (low resource usage).
    /// NOT recommended for production use.
    /// </summary>
    public static Argon2Parameters CreateForTesting()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,         // 32 KB
            Iterations = 3,             // 3 passes
            Parallelism = 4,            // 4 threads
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Validates all parameters according to RFC 9106 requirements.
    /// </summary>
    public void Validate()
    {
        if (Salt == null || Salt.Length < 8)
            throw new ArgumentException("Salt must be at least 8 bytes");

        if (MemorySizeKB < 8 * Parallelism)
            throw new ArgumentException($"Memory size must be at least {8 * Parallelism} KB (8 * Parallelism)");

        if (Iterations < 1)
            throw new ArgumentException("Iterations must be at least 1");

        if (Parallelism < 1 || Parallelism > 0xFFFFFF)
            throw new ArgumentException("Parallelism must be between 1 and 16777215");

        if (HashLength < 4)
            throw new ArgumentException("Hash length must be at least 4 bytes");
    }

    /// <summary>
    /// Creates a copy of the current parameters.
    /// </summary>
    public Argon2Parameters Clone()
    {
        return new Argon2Parameters
        {
            Type = Type,
            Version = Version,
            MemorySizeKB = MemorySizeKB,
            Iterations = Iterations,
            Parallelism = Parallelism,
            HashLength = HashLength,
            Salt = Salt != null ? (byte[])Salt.Clone() : null,
            Secret = Secret != null ? (byte[])Secret.Clone() : null,
            AssociatedData = AssociatedData != null ? (byte[])AssociatedData.Clone() : null
        };
    }
}
