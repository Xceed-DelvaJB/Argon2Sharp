namespace Argon2Sharp;

/// <summary>
/// Argon2 algorithm type.
/// </summary>
public enum Argon2Type
{
    /// <summary>
    /// Argon2d - data-dependent version, maximizes resistance to GPU attacks.
    /// Vulnerable to side-channel attacks.
    /// </summary>
    Argon2d = 0,

    /// <summary>
    /// Argon2i - data-independent version, resistant to side-channel attacks.
    /// Recommended for password hashing.
    /// </summary>
    Argon2i = 1,

    /// <summary>
    /// Argon2id - hybrid version combining Argon2i and Argon2d.
    /// Recommended by RFC 9106 as the primary choice for password hashing.
    /// First half-pass uses Argon2i, rest uses Argon2d.
    /// </summary>
    Argon2id = 2
}

/// <summary>
/// Argon2 version number.
/// </summary>
public enum Argon2Version
{
    /// <summary>
    /// Version 0x10 (1.0) - original version.
    /// </summary>
    Version10 = 0x10,

    /// <summary>
    /// Version 0x13 (1.3) - current version with fixes.
    /// This is the version specified in RFC 9106.
    /// </summary>
    Version13 = 0x13
}
