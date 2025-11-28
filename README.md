<div align="center">

# 🔐 Argon2Sharp

### Pure C# Implementation of Argon2 Password Hashing Algorithm

[![.NET 8.0](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![.NET 9.0](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![.NET 10.0](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Paol0B/Argon2id/dotnet.yml?branch=main&logo=github)](https://github.com/Paol0B/Argon2id/actions)
[![Tests](https://img.shields.io/badge/tests-425%20passed-success?logo=github)](https://github.com/Paol0B/Argon2id/actions)
[![License](https://img.shields.io/github/license/Paol0B/Argon2id?color=blue)](LICENSE)
[![RFC 9106](https://img.shields.io/badge/RFC-9106-orange)](https://www.rfc-editor.org/rfc/rfc9106.html)

A modern, high-performance, pure C# implementation of the Argon2 password hashing algorithm following RFC 9106 specification.

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[ASP.NET Core](#-aspnet-core-integration) •
[Advanced Features](#-advanced-features) •
[API Reference](#-api-reference)

</div>

---

## ✨ Features

### Core Features
- **Pure C#** - No native dependencies, runs anywhere .NET runs
- **RFC 9106 compliant** - Argon2d, Argon2i, Argon2id support
- **Immutable parameters** - Thread-safe `Argon2Parameters` sealed record
- **Builder pattern** - Fluent API for parameter construction
- **Span-based API** - Zero-allocation hot paths with `ReadOnlySpan<byte>`
- **PHC string format** - Standard format for password hash storage

### Performance
- **SIMD optimized** - AVX2 hardware acceleration for block operations
- **Parallel lane processing** - Multi-threaded hashing for high-security workloads
- **Async support** - Non-blocking operations with cancellation support
- **Batch processing** - Efficient bulk password hashing with progress reporting

### Security
- **Secure memory cleanup** - `CryptographicOperations.ZeroMemory()` for sensitive data
- **Constant-time comparison** - Timing attack resistant verification
- **Auto-rehashing** - Automatic hash upgrade when parameters change

### Enterprise
- **ASP.NET Core Identity** - Drop-in `IPasswordHasher<T>` integration
- **Dependency Injection** - Full DI support with `IServiceCollection` extensions
- **Key derivation (KDF)** - Derive encryption keys from passwords
- **Parameter tuning** - Auto-tune parameters for target execution time

## 📦 Installation

### NuGet Package (Coming Soon)

```bash
dotnet add package Argon2Sharp
dotnet add package Argon2Sharp.AspNetCore  # For ASP.NET Core Identity
```

### From Source

```bash
git clone https://github.com/Paol0B/Argon2id.git
cd Argon2id
dotnet build -c Release
```

## 🚀 Quick Start

### Option 1: PHC String Format (Recommended)

The simplest approach - hash and salt are stored together in a single string.

```csharp
using Argon2Sharp;

// Hash password (salt is auto-generated)
string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("MyPassword123");
// Output: $argon2id$v=19$m=19456,t=2,p=1$...salt...$...hash...

// Verify password
var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("MyPassword123", phcHash);
if (isValid)
{
    Console.WriteLine("Password is correct!");
}
```

### Option 2: Separate Hash and Salt

When you need to store hash and salt separately.

```csharp
using Argon2Sharp;

// Hash with auto-generated salt
var (hash, salt) = Argon2.HashPasswordWithSalt("MyPassword123");

// Store hash and salt in your database
await SaveToDatabase(userId, hash, salt);

// Later, verify the password
var parameters = Argon2Parameters.CreateDefault() with { Salt = storedSalt };
var argon2 = new Argon2(parameters);
bool isValid = argon2.Verify("MyPassword123", storedHash.AsSpan());
```

### Option 3: Custom Parameters with Builder

Full control over hashing parameters.

```csharp
using Argon2Sharp;

var parameters = Argon2Parameters.CreateBuilder()
    .WithType(Argon2Type.Argon2id)
    .WithMemorySizeKB(65536)    // 64 MB
    .WithIterations(4)
    .WithParallelism(4)
    .WithRandomSalt()
    .Build();

var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash("MyPassword123");
```

## 🌐 ASP.NET Core Integration

Argon2Sharp provides seamless integration with ASP.NET Core Identity.

### Basic Setup

```csharp
// Program.cs
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddArgon2PasswordHasher<ApplicationUser>();
```

### Custom Parameters

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddArgon2PasswordHasher<ApplicationUser>(options =>
    {
        options.MemorySizeKB = 65536;  // 64 MB
        options.Iterations = 4;
        options.Parallelism = 4;
        options.EnableAutoRehash = true;  // Auto-upgrade old hashes
    });
```

### Register Core Services

```csharp
// Register all Argon2Sharp services for DI
builder.Services.AddArgon2Sharp(options =>
{
    options.DefaultMemorySizeKB = 65536;
    options.DefaultIterations = 4;
});
```

This registers:
- `Argon2Parameters` (singleton)
- `Argon2KeyDerivation` (singleton)
- `Argon2ParameterTuner` (singleton)
- `Argon2RehashService` (singleton)
- `Argon2BatchHasher` (singleton)
- `Argon2AsyncHasher` (singleton)

## 🔧 Advanced Features

### Async Hashing

Non-blocking operations for web applications.

```csharp
var hasher = new Argon2AsyncHasher(Argon2Parameters.CreateDefault());

// Async hash
byte[] hash = await hasher.HashAsync("password");

// Async verify
bool isValid = await hasher.VerifyAsync("password", hash.AsMemory());

// With progress reporting
var progress = new Progress<double>(p => Console.WriteLine($"Progress: {p:P0}"));
hash = await hasher.HashAsync("password".AsMemory(), progress);

// Static async methods
var (hash, salt) = await Argon2AsyncHasher.HashPasswordWithSaltAsync("password");
string phcHash = await Argon2AsyncHasher.HashToPhcStringAsync("password");
var (isValid, params) = await Argon2AsyncHasher.VerifyPhcStringAsync("password", phcHash);
```

### Batch Processing

Efficiently hash multiple passwords (e.g., database migrations).

```csharp
var batchHasher = new Argon2BatchHasher();
var parameters = Argon2Parameters.CreateDefault();
var passwords = new[] { "pass1", "pass2", "pass3", "pass4" };

// With progress reporting
var progress = new Progress<BatchProgress>(p => 
    Console.WriteLine($"Completed: {p.Completed}/{p.Total}, ETA: {p.EstimatedTimeRemaining}"));

await foreach (var result in batchHasher.HashBatchAsync(passwords, parameters, progress))
{
    if (result.Success)
    {
        Console.WriteLine($"Password {result.Index}: {result.PhcHash}");
    }
}

// Or collect all results
var results = await Argon2BatchHasher.HashAllAsync(passwords, parameters);
```

### Key Derivation (KDF)

Derive encryption keys from passwords.

```csharp
var kdf = new Argon2KeyDerivation();

// Derive a 256-bit key for AES encryption
byte[] salt = Argon2.GenerateSalt(16);
byte[] aesKey = kdf.DeriveKey("masterPassword", salt, keyLength: 32);

// Derive multiple keys with domain separation
byte[][] keys = kdf.DeriveKeys(
    password: "masterPassword",
    salt: salt,
    keyLengths: new[] { 32, 64 },
    contexts: new[] { "encryption", "authentication" });

// Secure key that auto-zeros on disposal
using var secureKey = kdf.DeriveSecureKey("password", salt, 32);
EncryptData(data, secureKey.Key);
// Key is automatically zeroed when disposed
```

### Automatic Rehashing

Upgrade password hashes when security requirements change.

```csharp
var rehashService = new Argon2RehashService();
var newParams = Argon2Parameters.CreateHighSecurity();  // Stronger parameters

// During login - verify and rehash if needed
var result = rehashService.RehashIfNeeded(password, storedPhcHash, newParams);

if (result.Success)
{
    if (result.WasRehashed)
    {
        // Update database with stronger hash
        await UpdateUserHash(userId, result.NewPhcHash);
        Console.WriteLine($"Hash upgraded: {result.Reason}");
    }
    // Login successful
}

// Simple check without rehashing
var checkResult = Argon2RehashService.CheckRehash(storedHash, newParams);
if (checkResult.NeedsRehash)
{
    Console.WriteLine($"Rehash needed: {checkResult.Reason}");
}
```

### Parameter Tuning

Automatically find optimal parameters for your hardware.

```csharp
var tuner = new Argon2ParameterTuner();

// Find parameters for ~500ms hash time
var params = tuner.TuneParameters(
    targetTime: TimeSpan.FromMilliseconds(500),
    maxMemoryMB: 64,
    parallelism: 4);

// Get parameters for specific use cases
var webParams = tuner.SuggestParameters(Argon2UseCase.WebApplication);      // ~300ms
var mobileParams = tuner.SuggestParameters(Argon2UseCase.MobileApplication); // ~500ms
var desktopParams = tuner.SuggestParameters(Argon2UseCase.DesktopApplication); // ~1s
var secureParams = tuner.SuggestParameters(Argon2UseCase.HighSecurity);      // ~5s

// Estimate hash time for existing parameters
TimeSpan estimatedTime = tuner.EstimateHashTime(existingParams);

// Get system capability report
var report = tuner.GetSystemCapabilities(parallelism: 4);
Console.WriteLine($"CPU cores: {report.ProcessorCount}");
Console.WriteLine($"Fastest config: {report.FastestConfiguration}");
```

## 📖 API Reference

### Argon2Parameters

Immutable record for hash configuration.

```csharp
// Factory methods
Argon2Parameters.CreateDefault()       // 19 MB, 2 iterations, 1 parallelism
Argon2Parameters.CreateHighSecurity()  // 64 MB, 4 iterations, 4 parallelism
Argon2Parameters.CreateForTesting()    // 32 KB, 3 iterations (fast, NOT secure)

// Builder pattern
Argon2Parameters.CreateBuilder()
    .WithType(Argon2Type.Argon2id)
    .WithMemorySizeKB(65536)
    .WithIterations(4)
    .WithParallelism(4)
    .WithHashLength(32)
    .WithSalt(salt)              // Explicit salt
    .WithRandomSalt(16)          // Auto-generate salt
    .WithSecret(key)             // Optional secret key
    .WithAssociatedData(ctx)     // Optional associated data
    .Build();

// Modify with 'with' expression (immutable)
var modified = parameters with { Salt = newSalt };
```

### Algorithm Types

| Type | Description | Use Case |
|------|-------------|----------|
| `Argon2id` | Hybrid (default) | **Recommended** - Resistant to GPU and side-channel attacks |
| `Argon2i` | Data-independent | Side-channel sensitive environments |
| `Argon2d` | Data-dependent | Maximum GPU resistance (cryptocurrency, KDF) |

### Parameter Guidelines

| Parameter | Minimum | Default | High Security | Notes |
|-----------|---------|---------|---------------|-------|
| Memory | 8 KB | 19 MB | 64+ MB | Higher = more secure |
| Iterations | 1 | 2 | 4+ | Higher = slower but stronger |
| Parallelism | 1 | 1 | 4 | Match CPU cores |
| Hash Length | 4 bytes | 32 bytes | 32 bytes | 256-bit standard |
| Salt Length | 8 bytes | 16 bytes | 16 bytes | Always random |

### Recommended Parameters by Use Case

| Use Case | Memory | Iterations | Parallelism | Target Time |
|----------|--------|------------|-------------|-------------|
| Web Application | 64 MB | 3 | 1 | ~300ms |
| Mobile Application | 32 MB | 3 | 1 | ~500ms |
| Desktop Application | 256 MB | 4 | 4 | ~1s |
| Background Service | 512 MB | 4 | CPU cores | ~3s |
| High Security | 1 GB+ | 6+ | CPU cores | ~5s |

## ⚡ Performance

Benchmarks on Intel Core i7-12700H (14 cores), .NET 9.0, AVX2 enabled.

| Scenario | Memory | Iterations | Parallelism | Time |
|----------|--------|------------|-------------|------|
| Testing | 1 MB | 1 | 1 | ~53 μs |
| Default | 64 MB | 4 | 4 | ~15 ms |
| High Security | 256 MB | 6 | 4 | ~51 ms |

### Optimizations

- **SIMD/AVX2** - Hardware-accelerated block operations using `Vector<ulong>`
- **Parallel lanes** - Multi-threaded processing for p > 1
- **Loop unrolling** - Fully unrolled Blake2b rounds and permutations
- **Aggressive inlining** - All hot-path functions inlined
- **Hardware intrinsics** - Native `RotateRight` instructions
- **Memory pooling** - `ArrayPool<T>` for reduced GC pressure

## 🧪 Testing

```bash
dotnet test
```

425+ unit tests covering:
- RFC 9106 test vectors
- Edge cases and boundary conditions
- PHC format encoding/decoding
- Parameter validation
- Immutability enforcement
- Security and stress tests
- Interoperability tests
- Async operations

## 📁 Project Structure

```
Argon2Sharp/
├── src/
│   ├── Argon2Sharp/              # Core library
│   │   ├── Argon2.cs             # Main hasher class
│   │   ├── Argon2Parameters.cs   # Immutable parameters record
│   │   ├── Argon2PhcFormat.cs    # PHC string format
│   │   ├── Argon2AsyncHasher.cs  # Async operations
│   │   ├── Argon2BatchHasher.cs  # Batch processing
│   │   ├── Argon2KeyDerivation.cs # KDF functionality
│   │   ├── Argon2ParameterTuner.cs # Auto-tuning
│   │   ├── Argon2RehashService.cs # Hash upgrades
│   │   └── Abstractions/         # Interfaces
│   └── Argon2Sharp.AspNetCore/   # ASP.NET Core integration
│       ├── Argon2PasswordHasher.cs
│       └── DependencyInjection/
└── test/
    ├── Argon2Sharp.Tests/        # Unit tests
    ├── Argon2Sharp.Benchmarks/   # Performance benchmarks
    └── Argon2Sharp.Examples/     # Usage examples
```

## 🔒 Security Considerations

1. **Always use Argon2id** - It's the recommended variant by RFC 9106
2. **Use sufficient memory** - At least 19 MB for password hashing
3. **Generate random salts** - Never reuse salts
4. **Store complete PHC strings** - They include all parameters for verification
5. **Implement rehashing** - Upgrade hashes as security requirements evolve
6. **Clear sensitive data** - Use `SecureKeyBuffer` or manual zeroing

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 🔗 References

- [RFC 9106 - Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [PHC String Format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
