# Argon2Sharp v3.0 Specification

**Release Target:** Q1 2026  
**Status:** Feature Planning & Design Specification  
**Document Version:** 1.0 (Draft)

---

## 1. Executive Summary

Argon2Sharp v3.0 represents a major release focused on **modernization**, **performance**, and **security hardening**. This specification outlines the breaking changes, enhancements, and deprecations planned for the v3.0 release cycle.

### Key Objectives
- **API Modernization:** Transition to `Span<T>` and `ReadOnlyMemory<T>` as primary API surface.
- **Performance:** Optimize memory operations, introduce parallelization, and reduce allocations.
- **Security:** Enforce immutability in parameters, improve buffer cleanup, and harden sensitive data handling.
- **Quality:** Expand test coverage, establish CI/CD pipeline, add benchmarking infrastructure.
- **Developer Experience:** Provide comprehensive migration guides and improved documentation.

### Target Platforms
- **.NET 8.0+**
- **.NET 9.0**
- **.NET 10.0** 

---

## 2. Breaking Changes

### 2.1 Argon2Parameters Immutability

**Current Behavior (v2.x):**
```csharp
var parameters = new Argon2Parameters
{
    MemorySizeKB = 19456,
    Iterations = 2,
    // ... public mutable setters
};
```

**v3.0 Behavior (Breaking):**
```csharp
// Option A: Immutable record (recommended)
public sealed record Argon2Parameters(
    Argon2Type Type,
    Argon2Version Version,
    int MemorySizeKB,
    int Iterations,
    int Parallelism,
    int HashLength,
    byte[] Salt,
    byte[]? Secret = null,
    byte[]? AssociatedData = null);

// Option B: Builder pattern (alternative)
var parameters = new Argon2Parameters.Builder()
    .Type(Argon2Type.Argon2id)
    .MemorySizeKB(65536)
    .Iterations(3)
    .Parallelism(Environment.ProcessorCount)
    .Salt(saltSpan)
    .Build();
```

**Rationale:**
- Prevents accidental mutation and runtime errors.
- Enables thread-safe parameter passing.
- Encourages explicit, readable configuration.

**Migration Path:**
- Users modifying parameters post-creation must switch to Builder pattern or `Argon2Parameters.Create()` factory with new parameters.
- Deprecation warning: v2.x final patch will mark setters with `[Obsolete]`.

---

### 2.2 API Transition: Span-First Design

**Current Overloads (v2.x):**
```csharp
public byte[] Hash(string password)
public byte[] Hash(byte[] password)
public bool Verify(byte[] password, byte[] hash)
public void Hash(ReadOnlySpan<byte> password, Span<byte> output)  // exists internally
```

**v3.0 Primary API (Breaking):**
```csharp
// New primary API - Span/Memory-based
public byte[] Hash(ReadOnlySpan<byte> password)
public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
public bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<byte> hash)

// Convenience overloads (forward-compatible)
public byte[] Hash(string password) 
    => Hash(Encoding.UTF8.GetBytes(password));
public bool Verify(string password, ReadOnlySpan<byte> hash)
    => Verify(Encoding.UTF8.GetBytes(password), hash);
```

**Rationale:**
- Reduces heap allocations and memory copies.
- Aligns with modern .NET best practices (System.IO.Pipelines, System.Security.Cryptography patterns).
- Improves security by avoiding unnecessary buffer retention.

**Migration Impact:**
- `byte[]` overloads remain available but will be marked `[Obsolete]` pointing to `Span<byte>` equivalents.
- String parameter usage unaffected.

---

### 2.3 Argon2PhcFormat API Consolidation

**v3.0 Changes:**
```csharp
// Deprecated (v2.x)
public static byte[] Hash(string password, out byte[] salt)

// Recommended (v3.0)
public static (byte[] Hash, byte[] Salt) HashPasswordWithSalt(string password, Argon2Parameters parameters);

// New PHC-focused methods
public static string HashToPhcString(string password, Argon2Parameters parameters)
public static (bool IsValid, Argon2Parameters? Parameters) VerifyPhcString(string password, string phcString)
```

**Rationale:**
- PHC format is the preferred serialization standard for Argon2 hashes.
- Tuple returns eliminate out parameters and improve readability.
- Clear separation between byte-array and PHC string workflows.

---

## 3. New Features & Enhancements

### 3.1 Performance Optimizations

#### 3.1.1 Endianness & Bit Operations
**Status:** High Priority | **Complexity:** Low  
**Target:** Reduce `BitConverter` overhead

**Changes:**
```csharp
// Current (v2.x)
qwords[i] = BitConverter.ToUInt64(bytes.Slice(i * 8, 8));

// v3.0 (using BinaryPrimitives)
qwords[i] = BinaryPrimitives.ReadUInt64LittleEndian(
    bytes.Slice(i * 8, 8));
```

**Affected Modules:**
- `Argon2Core.BytesToQwords()` and `QwordsToBytes()`
- `Blake2b.LoadMessage()`
- `Blake2b.Compress()`

**Expected Impact:** 5-15% reduction in hashing time on benchmarks with small parameters.

#### 3.1.2 Memory Span Casting Optimization
**Status:** High Priority | **Complexity:** Medium

**Changes:**
- Use `MemoryMarshal.Cast<ulong, byte>()` for zero-copy qword ↔ byte conversions where alignment permits.
- Replace manual loops with bulk operations using `Buffer.BlockCopy()` or span slicing.

**Example (Before):**
```csharp
public static void QwordsToBytes(ReadOnlySpan<ulong> qwords, Span<byte> bytes)
{
    for (int i = 0; i < qwords.Length; i++)
    {
        BitConverter.TryWriteBytes(bytes.Slice(i * 8, 8), qwords[i]);
    }
}
```

**Example (After):**
```csharp
public static void QwordsToBytes(ReadOnlySpan<ulong> qwords, Span<byte> bytes)
{
    var bytesView = MemoryMarshal.AsBytes(qwords);
    bytesView.CopyTo(bytes);
}
```

**Expected Impact:** 10-20% throughput improvement in memory filling operations.

#### 3.1.3 Parallelization of Lane Processing
**Status:** Medium Priority | **Complexity:** High | **Backward Compatibility:** Maintained

**Changes:**
- Add optional `maxParallelTasks` parameter to `Argon2Parameters` (or `Argon2Engine` constructor).
- Replace serial lane iteration with `Parallel.For()` for segments where data-independent addressing is used (Argon2i/id).
- Implement dynamic task scheduler with configurable concurrency limits.

**Implementation Sketch:**
```csharp
private void FillMemoryBlocks(Span<ulong> memory)
{
    var parallelOptions = new ParallelOptions 
    { 
        MaxDegreeOfParallelism = _parameters.Parallelism 
    };

    for (int pass = 0; pass < _parameters.Iterations; pass++)
    {
        for (int slice = 0; slice < Argon2Core.SyncPoints; slice++)
        {
            Parallel.For(0, _parameters.Parallelism, parallelOptions, lane =>
            {
                FillSegment(memory, pass, lane, slice);
            });
        }
    }
}
```

**Expected Impact:** 2x-4x speedup on multi-core systems (subject to hardware and parameters).  
**Note:** Results remain deterministic; only execution order changes.

#### 3.1.4 ArrayPool Reuse & Buffer Cleanup
**Status:** High Priority | **Complexity:** Low

**Changes:**
- Ensure all `ArrayPool<ulong>.Shared.Rent()` calls are paired with `Shared.Return()` in `finally` blocks.
- Call `CryptographicOperations.ZeroMemory()` or `Span.Clear()` on sensitive buffers before returning to pool.
- Document and test pool lifecycle in benchmarks.

**Example:**
```csharp
var memory = ArrayPool<ulong>.Shared.Rent(_memoryBlocks * Argon2Core.QwordsInBlock);
try
{
    var memorySpan = memory.AsSpan(0, _memoryBlocks * Argon2Core.QwordsInBlock);
    // ... hash computation ...
}
finally
{
    // Zeroize before returning
    CryptographicOperations.ZeroMemory(memory.AsSpan(0, _memoryBlocks * Argon2Core.QwordsInBlock));
    ArrayPool<ulong>.Shared.Return(memory);
}
```

**Expected Impact:** Improved security posture; no performance degradation.

---

### 3.2 Security Hardening

#### 3.2.1 Immutable Parameter Objects
**Status:** Covered in §2.1  
**Impact:** Reduces runtime mutation vulnerabilities.

#### 3.2.2 Explicit Memory Zeroization
**Status:** High Priority | **Complexity:** Medium

**Changes:**
- Mark all sensitive spans/buffers with `[DebuggerBrowsable(DebuggerBrowsableState.Never)]` attribute.
- Implement `IDisposable` pattern for future `Argon2` class if stateful holds are added.
- Document best practices for applications using the library.

**New Method (Argon2):**
```csharp
/// <summary>
/// Zeroizes all internal sensitive buffers. 
/// Call this after hashing sensitive passwords in long-lived instances.
/// </summary>
public void ClearSensitiveData()
{
    // Clear any retained buffers if implementation changes
}
```

#### 3.2.3 Enhanced Input Validation
**Status:** Medium Priority | **Complexity:** Low

**Changes:**
- Validate salt length in `Argon2Parameters.Validate()` (already present; reinforce).
- Add checks for secret/associated data length limits (2^32 - 1 per RFC 9106).
- Throw `ArgumentOutOfRangeException` with detailed messages.

**Example:**
```csharp
public void Validate()
{
    if (Salt == null || Salt.Length < 8)
        throw new ArgumentException("Salt must be at least 8 bytes", nameof(Salt));
    
    if (Secret?.Length > uint.MaxValue)
        throw new ArgumentOutOfRangeException(nameof(Secret), "Secret too large");
    
    // ... existing checks ...
}
```

---

### 3.3 Testing & CI/CD Infrastructure

#### 3.3.1 Expanded Unit Test Coverage
**Status:** High Priority | **Complexity:** Medium

**Targets:**
- Add RFC 9106 official test vectors with expected hex outputs (not just determinism).
- Edge cases: empty password, maximum salt length, large memory sizes, minimum parameters.
- Cross-variant verification: ensure Argon2d/i/id produce different outputs with identical inputs.
- Reference block addressing: unit tests for `CalculateRefAreaSize()` boundary conditions.

**New Test File:** `Argon2Sharp.Tests/Argon2ReferenceBlockTests.cs`

#### 3.3.2 Benchmark Suite (BenchmarkDotNet)
**Status:** Medium Priority | **Complexity:** High | **Optional**

**New Project:** `test/Argon2Sharp.Benchmarks/`

**Scenarios:**
```csharp
[SimpleJob(warmupCount: 3, targetCount: 5)]
public class Argon2HashingBenchmarks
{
    [Params(32, 65536)]
    public int MemorySizeKB { get; set; }
    
    [Params(1, 4)]
    public int Parallelism { get; set; }
    
    private Argon2Parameters _parameters;
    
    [GlobalSetup]
    public void Setup() => _parameters = new Argon2Parameters { /* ... */ };
    
    [Benchmark]
    public byte[] HashDefault() => new Argon2(_parameters).Hash("password");
}
```

**Deliverables:** Markdown report with before/after performance metrics.

#### 3.3.3 GitHub Actions CI Pipeline
**Status:** High Priority | **Complexity:** Medium

**New File:** `.github/workflows/build-and-test.yml`

**Workflow:**
1. **Trigger:** Push to `main`, `develop`, and PR targets.
2. **Matrix:**
   - OS: `ubuntu-latest`, `windows-latest` (optional: `macos-latest`)
   - Framework: `net8.0`, `net9.0`, `net10.0`
3. **Steps:**
   - Checkout code
   - Setup .NET SDK
   - Run `dotnet build` with multi-targeting
   - Run `dotnet test` with coverage
   - Upload coverage to CodeCov or Codecov.io
   - Build NuGet package (Release config)
   - Publish to NuGet.org (tagged releases only)

**Example Job:**
```yaml
jobs:
  build-and-test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        framework: [net8.0, net9.0, net10.0]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: |
            8.0.x
            9.0.x
            10.0.x
      - run: dotnet build
      - run: dotnet test --no-build
```

#### 3.3.4 Code Coverage Reporting
**Status:** Medium Priority

**Configuration:** Update `coverlet.runsettings` to enforce minimum coverage thresholds (e.g., 85%).

---

### 3.4 Documentation & Developer Experience

#### 3.4.1 Updated README.md
**Status:** High Priority

**Sections to Add/Update:**
- **API Examples:** Modernize to use `Span<byte>` and immutable parameters.
- **Migration Guide (v2.x → v3.0):** Clear breaking changes and side-by-side examples.
- **Performance Notes:** Recommended parameters for different scenarios (web, desktop, CLI).
- **Security Considerations:** Buffer cleanup, salt generation best practices.
- **Contribution Guidelines:** How to run tests, benchmarks, and build locally.

**Example New Section:**
```markdown
### Recommended Parameters

#### Web Applications
- **Memory:** 19 MB (19456 KB)
- **Iterations:** 2
- **Parallelism:** 1 (or CPU cores / 2 if on multi-core server)
- **Hash Length:** 32 bytes
- **Time per Hash:** ~500 ms (single-threaded)

#### Desktop Applications
- **Memory:** 64 MB (65536 KB)
- **Iterations:** 3
- **Parallelism:** 4
- **Hash Length:** 32 bytes
- **Time per Hash:** ~5-10s (depending on CPU cores)
```

#### 3.4.2 CHANGELOG.md
**Status:** High Priority

**Format:** Keep Change Log v1.1.0 standard.

**Content:**
```markdown
## [3.0.0] - 2026-Q1

### Breaking Changes
- `Argon2Parameters` now immutable; use `Argon2Parameters.Builder` for configuration.
- `Hash(byte[])` and `Verify(byte[], byte[])` marked `[Obsolete]`; migrate to `Span<byte>` overloads.
- Static `HashPassword()` method signature updated to accept `Argon2Parameters`.

### Added
- `Span<T>` and `ReadOnlyMemory<T>` primary API surface.
- Parallel lane processing for multi-core systems (configurable).
- Builder pattern for `Argon2Parameters`.
- Official RFC 9106 test vectors with expected outputs.
- BenchmarkDotNet suite for performance tracking.
- GitHub Actions CI/CD pipeline.

### Changed
- Replaced `BitConverter` with `BinaryPrimitives` for endianness operations (+15% throughput).
- Memory layout optimizations using `MemoryMarshal.Cast()`.
- Enhanced input validation with detailed error messages.

### Fixed
- Buffer zeroization on ArrayPool returns (security hardening).

### Deprecated
- `Hash(byte[])`, `Verify(byte[], byte[])` – use `Span<byte>` equivalents.
- Mutable setters on `Argon2Parameters` – use immutable pattern.

## [2.0.0] - Previous Release
...
```

#### 3.4.3 API Documentation & XML Comments
**Status:** Medium Priority

**Actions:**
- Complete XML documentation comments for all public members.
- Add `/// <exception>` tags for validation exceptions.
- Include examples in summary for frequently-used methods.
- Generate NuGet `.xml` package documentation automatically.

**Example:**
```csharp
/// <summary>
/// Computes an Argon2 hash of the provided password using the configured parameters.
/// </summary>
/// <param name="password">The password to hash as a UTF-8 encoded span.</param>
/// <returns>A byte array containing the computed hash of length <see cref="Argon2Parameters.HashLength"/>.</returns>
/// <exception cref="ArgumentNullException">Thrown if parameters are not configured.</exception>
/// <exception cref="ArgumentOutOfRangeException">Thrown if parameters fail validation.</exception>
/// <remarks>
/// The hash is deterministic for identical inputs and parameters.
/// This method does not modify the password buffer; sensitive data cleanup is caller's responsibility.
/// </remarks>
/// <example>
/// <code>
/// var parameters = Argon2Parameters.CreateDefault();
/// parameters.Salt = Argon2.GenerateSalt(16);
/// var hasher = new Argon2(parameters);
/// byte[] hash = hasher.Hash("mypassword"u8);
/// </code>
/// </example>
public byte[] Hash(ReadOnlySpan<byte> password)
```

---

## 4. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Implement `Argon2Parameters` immutability (record or builder pattern).
- [ ] Add `Span<byte>` overloads to `Argon2` public API.
- [ ] Introduce deprecation attributes on v2.x methods.
- [ ] Update XML comments for core public members.

### Phase 2: Performance (Weeks 3-4)
- [ ] Replace `BitConverter` with `BinaryPrimitives`.
- [ ] Implement `MemoryMarshal.Cast()` optimizations.
- [ ] Add parallelization to `FillMemoryBlocks()`.
- [ ] Buffer zeroization and ArrayPool cleanup.

### Phase 3: Testing & Quality (Weeks 5-6)
- [ ] Expand RFC 9106 test vectors suite.
- [ ] Create BenchmarkDotNet project and baseline measurements.
- [ ] Establish GitHub Actions CI/CD pipeline.
- [ ] Code coverage reporting setup.

### Phase 4: Documentation & Polish (Weeks 7-8)
- [ ] Write migration guide for v2.x → v3.0.
- [ ] Update README.md with new API examples.
- [ ] Finalize CHANGELOG.md.
- [ ] Review and merge documentation PRs.

### Phase 5: Release Preparation (Weeks 9-10)
- [ ] Release Candidate (RC1) build and testing.
- [ ] Community feedback period (2 weeks).
- [ ] Final bug fixes and polish.
- [ ] Publish v3.0.0 to NuGet.org.

---

## 5. Migration Guide (v2.x → v3.0)

### 5.1 Parameter Configuration

**v2.x:**
```csharp
var parameters = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,
    MemorySizeKB = 19456,
    Iterations = 2,
    Parallelism = 1,
    HashLength = 32,
    Salt = saltBytes
};
```

**v3.0 (Immutable Record):**
```csharp
var parameters = new Argon2Parameters(
    Type: Argon2Type.Argon2id,
    Version: Argon2Version.Version13,
    MemorySizeKB: 19456,
    Iterations: 2,
    Parallelism: 1,
    HashLength: 32,
    Salt: saltBytes);
```

**v3.0 (Builder Pattern, Alternative):**
```csharp
var parameters = Argon2Parameters.CreateBuilder()
    .Type(Argon2Type.Argon2id)
    .MemorySizeKB(19456)
    .Iterations(2)
    .Parallelism(1)
    .HashLength(32)
    .Salt(saltBytes)
    .Build();
```

### 5.2 Hashing API

**v2.x:**
```csharp
byte[] password = Encoding.UTF8.GetBytes("mypassword");
var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash(password);  // byte[] overload
```

**v3.0:**
```csharp
ReadOnlySpan<byte> password = "mypassword"u8;  // UTF-8 string literal
var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash(password);  // Span<byte> overload

// Or with output buffer pre-allocated:
Span<byte> outputBuffer = new byte[32];
argon2.Hash(password, outputBuffer);
```

### 5.3 Static Methods

**v2.x:**
```csharp
byte[] hash = Argon2.HashPassword("password", out byte[] salt);
bool isValid = Argon2.VerifyPassword("password", hash, salt);
```

**v3.0:**
```csharp
var parameters = Argon2Parameters.CreateDefault();
var (hash, salt) = Argon2.HashPasswordWithSalt("password", parameters);
bool isValid = Argon2.VerifyPassword("password", hash, parameters);
```

### 5.4 PHC String Format

**v2.x:**
```csharp
var parameters = Argon2Parameters.CreateDefault();
parameters.Salt = Argon2.GenerateSalt(16);
string phcString = Argon2PhcFormat.Encode(hash, salt, ...);
bool verified = Argon2PhcFormat.VerifyPassword("password", phcString);
```

**v3.0:**
```csharp
var parameters = Argon2Parameters.CreateDefault();
string phcString = Argon2PhcFormat.HashToPhcString("password", parameters);
(bool isValid, var recoveredParams) = Argon2PhcFormat.VerifyPhcString("password", phcString);
```

---

## 6. Acceptance Criteria

### 6.1 Functional Requirements
- [x] All existing test cases pass without modification.
- [ ] New `Span<byte>` API overloads available and functional.
- [ ] `Argon2Parameters` immutable in v3.0 release build.
- [ ] Parallelization optional and configurable, results deterministic.
- [ ] RFC 9106 test vectors pass with expected hash outputs.
- [ ] Performance improvements quantified (benchmarks published).

### 6.2 Code Quality Requirements
- [ ] Code coverage ≥ 85% (enforced via CI).
- [ ] Zero compiler warnings (warnings as errors enabled).
- [ ] All public APIs documented with XML comments.
- [ ] Deprecation warnings guide users to v3.0 APIs.

### 6.3 Documentation Requirements
- [ ] Migration guide available and comprehensive.
- [ ] README.md includes v3.0 examples and recommended parameters.
- [ ] CHANGELOG.md documents all breaking changes and new features.
- [ ] API documentation complete and generated in NuGet package.

### 6.4 Security Requirements
- [ ] All sensitive buffers zeroized before returning to pool or GC.
- [ ] Input validation enhanced with descriptive error messages.
- [ ] Security best practices documented.

### 6.5 Release Requirements
- [ ] GitHub Actions CI passes on all target frameworks and platforms.
- [ ] Release candidate (RC) available for community testing.
- [ ] Release notes published with migration instructions.
- [ ] NuGet package published with symbols and documentation.

---

## 7. Known Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| Breaking API changes cause user frustration | High | Medium | Comprehensive migration guide, long deprecation period in v2.x final patch |
| Parallelization introduces race conditions | Medium | High | Extensive multi-threaded testing, stress tests, thread-safe memory allocation |
| Performance optimizations regress on some platforms | Medium | Medium | Multi-platform benchmarking (Linux, Windows, macOS), CI matrix includes multiple configs |
| Memory zeroization incomplete (security issue) | Low | High | Code review checklist, automated buffer clearing in finally blocks, security audit |

---

## 8. Success Metrics

1. **Performance:** 15-25% throughput improvement on standard benchmarks (vs. v2.x).
2. **Adoption:** 50%+ of active users adopt v3.0 within 6 months of release.
3. **Quality:** Zero critical security issues in first 3 months of release.
4. **Test Coverage:** ≥ 85% code coverage maintained or improved.
5. **Documentation:** Positive community feedback on clarity of migration guide.

---

## 9. References

- [RFC 9106: Argon2 Password Hashing Algorithm](https://tools.ietf.org/html/rfc9106)
- [System.Security.Cryptography API Docs](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography)
- [Span<T> and Memory<T> Best Practices](https://docs.microsoft.com/en-us/archive/msdn-magazine/2018-january/csharp-all-about-span-exploring-a-new-net-mainstay)
- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning 2.0.0](https://semver.org/)

---

## 10. Document History

| Version | Date | Author | Status | Changes |
|---------|------|--------|--------|---------|
| 1.0 | 2025-11-12 | Engineering Team | Draft | Initial specification for v3.0 |

---

**Next Review:** 2025-11-26 (planned)  
**Last Updated:** 2025-11-12

