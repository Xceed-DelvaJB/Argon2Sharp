# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[3.0.0]: https://github.com/Paol0B/Argon2id/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/Paol0B/Argon2id/releases/tag/v2.0.0
