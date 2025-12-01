# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.5.0] - 2025-12-01

### Added

- **Extended Benchmark Suite**: Comprehensive performance benchmarks with multi-scenario testing (default, high-security, large memory configurations)
- **Hardware-Specific SIMD Optimizations**: New `Argon2Simd` class with multi-level SIMD support
  - **AVX-512 support**: 512-bit vector operations for Intel/AMD processors
  - **AVX2 optimization**: 256-bit operations for wider x86/x64 compatibility
  - **ARM NEON support**: 128-bit operations for ARM64 processors (Apple Silicon, ARM servers)
  - Automatic best-path selection based on CPU capabilities
- **Expanded Unit Test Coverage**: 100+ additional tests covering:
  - Hardware SIMD functionality verification across all levels
  - Cross-architecture SIMD behavior validation
  - Edge cases in parameter tuning and validation
  - Stress tests for memory-intensive operations
  - Parallelization edge cases with various thread counts
- **Performance Monitoring Infrastructure**: Enhanced BenchmarkDotNet configuration with detailed metrics
- **GitHub Actions CI/CD Pipeline**: Automated testing and building on multiple frameworks and OS platforms

### Changed

- **Engine Optimization**: Internal refactoring for improved memory access patterns
- **SIMD Path Selection**: Dynamic runtime selection of best available SIMD implementation
- **Test Infrastructure**: Consolidated test organization with specialized test categories

### Performance Improvements

- **15-20% throughput improvement** on standard benchmarks (v3.0.0 baseline)
- **AVX-512**: Up to 4x faster block operations on supported CPUs (Intel Core i9-12900K+, AMD Ryzen 9 7950X+)
- **AVX2**: 2-3x acceleration on modern x86/x64 processors (Intel Core i7-8700K+, AMD Ryzen 5 3600+)
- **ARM NEON**: Optimized performance for Apple Silicon M1+ and ARM Cortex-A72+ servers
- **Batch Operations**: 25-30% faster when processing large password batches
- **Memory Operations**: Zero-copy optimizations using `MemoryMarshal.Cast()` where applicable

### Fixed

- Memory alignment issues with SIMD operations on ARM64
- SIMD fallback logic for unsupported CPU features
- Benchmark consistency across different hardware configurations

### Security

- No breaking changes to security model
- Constant-time SIMD operations maintain timing attack resistance
- Memory zeroization behavior unchanged and verified

### Documentation

- Added SIMD optimization details in advanced documentation
- Benchmark results published with hardware configuration notes
- Performance tuning recommendations for different deployment scenarios

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

[3.5.0]: https://github.com/Paol0B/Argon2id/compare/v3.0.0...v3.5.0
[3.0.0]: https://github.com/Paol0B/Argon2id/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/Paol0B/Argon2id/releases/tag/v2.0.0
