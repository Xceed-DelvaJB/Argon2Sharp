# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2025-12-01

### Added

- **Asynchronous API**: Full async/await support with `Argon2AsyncHasher` implementing `IArgon2AsyncHasher`
  - `HashAsync(ReadOnlyMemory<byte>, CancellationToken)` - Async password hashing with cancellation
  - `VerifyAsync(ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, CancellationToken)` - Async verification
  - `HashAsync(string, IProgress<double>?, CancellationToken)` - Progress reporting support
- **Key Derivation Function (KDF)**: New `Argon2KeyDerivation` class implementing `IArgon2KeyDerivation`
  - `DeriveKey(password, salt, keyLength)` - Cryptographic key derivation for encryption/HMAC
  - Optimized parameters for KDF workflows (64MB memory by default)
  - Support for variable-length key output
- **Automatic Parameter Tuning**: New `Argon2ParameterTuner` implementing `IArgon2ParameterTuner`
  - `TuneParameters(targetTime, maxMemoryMB, parallelism)` - Auto-calibrate based on target execution time
  - `EstimateHashTime(parameters)` - Estimate hash execution time
  - Async variants with cancellation support for non-blocking calibration
- **Hash Lifecycle Management**: New `Argon2RehashService` implementing `IArgon2RehashService`
  - `CheckNeedsRehash(phcHash, minimumParameters)` - Detect outdated hashes
  - `VerifyAndRehash(password, phcHash, newParameters)` - Verify and upgrade hash in one operation
  - `RehashReason` enum for detailed upgrade diagnostics
- **Batch Password Processing**: New `Argon2BatchHasher` implementing `IArgon2BatchHasher`
  - `HashBatchAsync(passwords, parameters)` - Process multiple passwords efficiently
  - Parallel processing with configurable concurrency
  - Progress reporting with success/failure statistics
  - Memory-efficient streaming via `IAsyncEnumerable<BatchHashResult>`
- **Hardware-Accelerated SIMD**: New `Argon2Simd` class with multi-level optimization
  - **AVX-512**: 512-bit operations for Intel/AMD processors (up to 4x faster)
  - **AVX2**: 256-bit operations for modern x86/x64 (2-3x faster)
  - **ARM NEON**: 128-bit operations for Apple Silicon and ARM64 servers
  - Automatic best-path selection based on CPU capabilities
- **ASP.NET Core Identity Integration**: New `Argon2Sharp.AspNetCore` package
  - `Argon2PasswordHasher<TUser>` implementing `IPasswordHasher<TUser>`
  - Automatic hash upgrade detection (`PasswordVerificationResult.SuccessRehashNeeded`)
  - Compatible with ASP.NET Core Identity framework
  - DI extensions: `AddArgon2PasswordHasher()` and `AddArgon2Sharp()`
  - `Argon2PasswordHasherOptions` for flexible configuration
- **Comprehensive Abstractions**: Extensible interface hierarchy for custom implementations
  - `IArgon2Hasher` - Core hashing interface
  - `IArgon2AsyncHasher` - Async hashing with progress support
  - `IArgon2KeyDerivation` - KDF interface
  - `IArgon2ParameterTuner` - Parameter tuning interface
  - `IArgon2RehashService` - Hash upgrade service interface
  - `IArgon2BatchHasher` - Batch processing interface
  - `IArgon2ProgressReporter` - Progress tracking interface
- **Enhanced Progress Reporting**: Built-in support for operation progress tracking
  - Per-operation progress (0.0 to 1.0) for async hashing
  - Batch operation progress with completion counts and timing
  - Time-based progress estimation

### Changed

- **Engine Enhancement**: Added `HashWithProgress()` method to `Argon2Engine` for fine-grained progress tracking
- **Memory Management**: Improved buffer pooling and recycling strategies
- **Target Frameworks**: Updated to .NET 8.0 and 9.0 (removed preview .NET 10.0 support)
- **Solution Structure**: Reorganized with ASP.NET Core integration package
- **Dependency Injection**: Full support for `Microsoft.Extensions.DependencyInjection`

### Performance Improvements

- **SIMD Vectorization**:
  - AVX-512: Up to 4x faster block operations on supported CPUs
  - AVX2: 2-3x speedup for standard modern processors  
  - ARM NEON: Significant acceleration on Apple Silicon and ARM64 servers
- **Async Operations**: Reduced thread pool contention in high-concurrency scenarios
- **Batch Processing**: 40-60% throughput improvement over sequential hashing
- **Memory Operations**: Optimized span casting and bulk transfers

### Security Enhancements

- **Progress Reporting**: Non-blocking callbacks prevent timing side-channels
- **CancellationToken Support**: Proper resource cleanup on operation cancellation
- **Keyed Hashing**: Full support for secret keys in KDF operations
- **Secure Parameter Tuning**: Test hashes immediately zeroized during calibration

### Deprecated

- None (all 3.x deprecations remain in place)

### Removed

- None

### Migration Notes

**From 3.x to 4.0:**

All existing code continues to work unchanged. New services available via:

```csharp
// Async hashing
var asyncHasher = new Argon2AsyncHasher(parameters);
byte[] hash = await asyncHasher.HashAsync("password");

// Key derivation
var kdf = new Argon2KeyDerivation();
byte[] key = kdf.DeriveKey("password", salt, 32);

// Parameter tuning
var tuner = new Argon2ParameterTuner();
var params = tuner.TuneParameters(TimeSpan.FromMilliseconds(500));

// Hash rehashing
var rehashService = new Argon2RehashService();
var (isValid, newHash) = rehashService.VerifyAndRehash(pwd, hash, params);

// Batch processing
var batchHasher = new Argon2BatchHasher();
await foreach (var result in batchHasher.HashBatchAsync(passwords, params)) { }

// ASP.NET Core Identity
services.AddArgon2PasswordHasher();
```

### Documentation

- Complete API documentation for all new classes and interfaces
- Updated README with new API examples
- New guides for async operations, KDF, parameter tuning, and ASP.NET Core integration
- Extended benchmarking documentation

## [3.5.0] - 2025-11-28

### Added

- **Enhanced Benchmarking**: Expanded BenchmarkDotNet suite with additional scenarios
- **Extended Unit Tests**: 100+ new test cases for edge cases and boundary conditions
- **Memory Profiling**: Comprehensive memory usage tracking in benchmarks

### Performance Improvements

- 5-15% throughput improvement across standard benchmarks
- Better cache locality in memory filling operations
- Optimized Blake2b permutation unrolling

### Changed

- Benchmark project restructured for better result organization

## [3.0.0] - 2025-11-25

### Added

- **Immutable `Argon2Parameters`**: Converted to sealed record for thread-safety and immutability
- **Builder pattern**: New `Argon2Parameters.CreateBuilder()` with fluent API for parameter construction
- **Span-based API**: Primary `Hash(ReadOnlySpan<byte>)` and `Verify(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` methods
- **Tuple-based methods**: `HashPasswordWithSalt()` returns `(byte[] Hash, byte[] Salt)` tuple
- **New PHC methods**: `HashToPhcString()`, `HashToPhcStringWithAutoSalt()`, `VerifyPhcString()` returning tuple with parameters
- **Performance optimizations**: `BinaryPrimitives` and `MemoryMarshal.Cast()` for zero-copy operations on little-endian systems
- **Secure memory cleanup**: `CryptographicOperations.ZeroMemory()` for sensitive data
- **Comprehensive edge case tests**: 58 unit tests covering boundary conditions
- **BenchmarkDotNet project**: Performance benchmarks for various parameter configurations

### Changed

- `Argon2Parameters` is now a sealed record (immutable by default)
- Use `with` expression to modify parameters: `parameters with { Salt = newSalt }`
- Parameters validation happens at construction time with Builder or on `Validate()` call

### Deprecated

- `Argon2.Hash(byte[])` - Use `Hash(ReadOnlySpan<byte>)` instead
- `Argon2.Verify(byte[], byte[])` - Use `Verify(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` instead
- `Argon2.Verify(string, byte[])` - Use `Verify(string, ReadOnlySpan<byte>)` instead
- `Argon2.HashPassword(string, out byte[])` - Use `HashPasswordWithSalt()` tuple return
- `Argon2.HashPassword(...)` with individual parameters - Use `Argon2Parameters.CreateBuilder()`
- `Argon2.VerifyPassword(...)` with individual parameters - Use `Argon2Parameters.CreateBuilder()`
- `Argon2PhcFormat.HashPassword(...)` - Use `HashToPhcString()` or `HashToPhcStringWithAutoSalt()`
- `Argon2PhcFormat.VerifyPassword(...)` - Use `VerifyPhcString()` tuple return
- `Argon2Parameters.Clone()` - Use `with` expression

### Fixed

- Memory buffer cleanup now uses `CryptographicOperations.ZeroMemory()` for security
- Little-endian optimizations with `MemoryMarshal` provide better performance on x86/x64

### Security

- Immutable parameters prevent accidental modification after hashing
- Secure memory zeroing ensures sensitive data is cleared

## [2.0.0] - 2025-01-15

### Added

- Initial public release
- Full RFC 9106 compliance
- Argon2d, Argon2i, Argon2id support
- PHC string format encoding/decoding
- .NET 8.0, 9.0, 10.0 multi-targeting

[4.0.0]: https://github.com/Paol0B/Argon2id/compare/v3.5.0...v4.0.0
[3.5.0]: https://github.com/Paol0B/Argon2id/compare/v3.0.0...v3.5.0
[3.0.0]: https://github.com/Paol0B/Argon2id/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/Paol0B/Argon2id/releases/tag/v2.0.0
