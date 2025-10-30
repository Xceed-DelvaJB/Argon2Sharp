# Argon2Sharp

A pure C# implementation of the Argon2 password hashing algorithm based on RFC 9106 specification. Supports Argon2d, Argon2i, and Argon2id variants with .NET 9.

## Features

- ✅ **Pure C# Implementation** - No native dependencies
- ✅ **RFC 9106 Compliant** - Follows the latest Argon2 specification
- ✅ **All Variants Supported** - Argon2d, Argon2i, and Argon2id
- ✅ **Modern C# Syntax** - Built with .NET 9 and latest C# features
- ✅ **High Performance** - Optimized with Span<T> and stackalloc
- ✅ **Memory Safe** - Automatic sensitive data cleanup
- ✅ **PHC String Format** - Standard encoding/decoding support
- ✅ **Flexible API** - Simple and advanced usage options

## Installation

```bash
# Clone the repository
git clone https://github.com/Paol0B/Argon2Sharp.git
cd Argon2Sharp

# Build the library
dotnet build Argon2Sharp/Argon2Sharp.csproj
```

## Quick Start

### Basic Password Hashing

```csharp
using Argon2Sharp;

// Hash a password with default parameters
byte[] hash = Argon2.HashPassword("MyPassword123", out byte[] salt);

// Verify password
var parameters = Argon2Parameters.CreateDefault();
parameters.Salt = salt;
var argon2 = new Argon2(parameters);
bool isValid = argon2.Verify("MyPassword123", hash);
```

### Using PHC String Format

```csharp
using Argon2Sharp;

// Hash password to PHC format string
string phcHash = Argon2PhcFormat.HashPassword("MyPassword123");
// Output: $argon2id$v=19$m=19456,t=2,p=1$...salt...$...hash...

// Verify password
bool isValid = Argon2PhcFormat.VerifyPassword("MyPassword123", phcHash);
```

### Custom Parameters

```csharp
using Argon2Sharp;

var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,        // Algorithm variant
    MemorySizeKB = 65536,               // 64 MB
    Iterations = 4,                     // Time cost
    Parallelism = 4,                    // Threads
    HashLength = 32,                    // Output size
    Salt = Argon2.GenerateSalt(16)     // 16-byte salt
};

var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash("MyPassword123");
```

### High Security Configuration

```csharp
using Argon2Sharp;

// Use high security preset
var parameters = Argon2Parameters.CreateHighSecurity();
parameters.Salt = Argon2.GenerateSalt(16);

var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash("MyPassword123");
```

### With Secret Key and Associated Data

```csharp
using Argon2Sharp;
using System.Text;

var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,
    MemorySizeKB = 32768,
    Iterations = 3,
    Parallelism = 4,
    HashLength = 32,
    Salt = Argon2.GenerateSalt(16),
    Secret = Encoding.UTF8.GetBytes("app-secret-key"),
    AssociatedData = Encoding.UTF8.GetBytes("user-context")
};

var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash("MyPassword123");
```

## Algorithm Variants

### Argon2id (Recommended)

```csharp
var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,  // Hybrid: resistant to both GPU and side-channel attacks
    // ... other parameters
};
```

**Best for:** Password hashing in most applications (RFC 9106 recommendation)

### Argon2i

```csharp
var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2i,   // Data-independent: side-channel resistant
    // ... other parameters
};
```

**Best for:** Password hashing where side-channel attacks are a concern

### Argon2d

```csharp
var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2d,   // Data-dependent: maximum GPU resistance
    // ... other parameters
};
```

**Best for:** Cryptocurrency mining, KDF where side-channels aren't a concern

## Parameter Guidelines

### Recommended for Password Hashing (RFC 9106)

```csharp
var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,
    MemorySizeKB = 19456,      // 19 MB (minimum recommended)
    Iterations = 2,             // 2 passes (minimum recommended)
    Parallelism = 1,            // Single-threaded
    HashLength = 32             // 256-bit output
};
```

### Parameter Constraints

- **Memory Size**: Minimum 8 KB, recommended ≥ 19 MB
- **Iterations**: Minimum 1, recommended ≥ 2
- **Parallelism**: Between 1 and 16,777,215
- **Hash Length**: Minimum 4 bytes, typical 32 or 64 bytes
- **Salt Length**: Minimum 8 bytes, recommended ≥ 16 bytes

## API Reference

### Argon2 Class

Main class for hashing operations.

```csharp
public sealed class Argon2
{
    public Argon2(Argon2Parameters parameters);
    
    public byte[] Hash(string password);
    public byte[] Hash(byte[] password);
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output);
    
    public bool Verify(string password, byte[] hash);
    public bool Verify(byte[] password, byte[] hash);
    
    public static byte[] HashPassword(string password, out byte[] salt);
    public static bool VerifyPassword(string password, byte[] hash, byte[] salt, ...);
    public static byte[] GenerateSalt(int length = 16);
}
```

### Argon2Parameters Class

Configuration parameters for Argon2.

```csharp
public sealed class Argon2Parameters
{
    public Argon2Type Type { get; set; }
    public Argon2Version Version { get; set; }
    public int MemorySizeKB { get; set; }
    public int Iterations { get; set; }
    public int Parallelism { get; set; }
    public int HashLength { get; set; }
    public byte[]? Salt { get; set; }
    public byte[]? Secret { get; set; }
    public byte[]? AssociatedData { get; set; }
    
    public static Argon2Parameters CreateDefault();
    public static Argon2Parameters CreateHighSecurity();
    public static Argon2Parameters CreateForTesting();
}
```

### Argon2PhcFormat Class

PHC string format encoding/decoding.

```csharp
public static class Argon2PhcFormat
{
    public static string Encode(byte[] hash, byte[] salt, ...);
    public static bool TryDecode(string phcString, out ...);
    public static string HashPassword(string password, ...);
    public static bool VerifyPassword(string password, string phcHash);
}
```

## Performance

Performance varies based on parameters. Examples on a typical modern CPU:

| Memory | Iterations | Parallelism | Approximate Time |
|--------|-----------|-------------|------------------|
| 32 KB  | 3         | 4           | ~5-10 ms         |
| 1 MB   | 3         | 4           | ~50-100 ms       |
| 19 MB  | 2         | 1           | ~100-200 ms      |
| 64 MB  | 4         | 4           | ~500-1000 ms     |

## Security Considerations

1. **Use Argon2id** for password hashing (RFC 9106 recommendation)
2. **Generate random salts** using `Argon2.GenerateSalt()`
3. **Store salt separately** alongside the hash
4. **Tune parameters** based on your security requirements and available resources
5. **Use constant-time comparison** (built-in via `Verify` methods)
6. **Consider memory hardness** when choosing parameters

## Testing

```bash
# Run all tests
dotnet test Argon2Sharp.Tests/Argon2Sharp.Tests.csproj

# Run examples
dotnet run --project Argon2Sharp.Examples/Argon2Sharp.Examples.csproj
```

## Examples

See the `Argon2Sharp.Examples` project for comprehensive usage examples:

- Basic password hashing
- Password verification
- PHC string format usage
- Custom parameters
- Different algorithm variants
- Performance benchmarking

## Architecture

```
Argon2Sharp/
├── Core/
│   ├── Blake2b.cs          # Blake2b-512 hash function
│   ├── Argon2Core.cs       # Core compression functions
│   └── Argon2Engine.cs     # Main algorithm implementation
├── Argon2.cs               # Public API
├── Argon2Parameters.cs     # Configuration
├── Argon2Types.cs          # Enumerations
└── Argon2PhcFormat.cs      # PHC string format
```

## Implementation Details

- **Blake2b**: Pure C# implementation of Blake2b-512 for internal hashing
- **Memory Layout**: Efficient block-based memory management with pooling
- **Parallelism**: Supports multi-threaded operation via `Parallelism` parameter
- **Memory Safety**: Automatic cleanup of sensitive data using `ArrayPool`
- **Zero Dependencies**: No external packages required

## Compliance

This implementation follows:
- RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:
- Code follows C# coding conventions
- All tests pass
- New features include tests
- Documentation is updated

## References

- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 7693 - BLAKE2](https://www.rfc-editor.org/rfc/rfc7693.html)
- [Argon2 Official](https://github.com/P-H-C/phc-winner-argon2)

## Author

Paolo - 2025

## Acknowledgments

Based on the Argon2 specification by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich.
