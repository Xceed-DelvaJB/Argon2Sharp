# Argon2Sharp v3.0 - Implementation Checklist

**Start Date:** TBD  
**Target Release:** Q1 2026  
**Estimated Duration:** 8-10 weeks

---

## Phase 1: Foundation (Weeks 1-2)

### Task 1.1: Immutable Argon2Parameters
- [ ] Decide implementation approach: `sealed record` vs. `sealed class` + Builder
- [ ] Create immutable `Argon2Parameters` structure
- [ ] Implement `Argon2Parameters.Builder` with fluent API
- [ ] Implement factory methods: `CreateDefault()`, `CreateHighSecurity()`, `CreateForTesting()`, `CreateBuilder()`
- [ ] Add validation in `Validate()` method
- [ ] Update all internal usages to use immutable parameters
- [ ] Mark v2.x setters with `[Obsolete]` attribute (if keeping for backward compat)
- [ ] Unit tests: parameter construction, builder pattern, immutability enforcement
- [ ] **PR Review:** Code review for API design consistency

**Success Criteria:**
- All existing tests pass with new immutable parameters
- Builder pattern is intuitive and well-documented

---

### Task 1.2: Span<T> Primary API
- [ ] Add public `byte[] Hash(ReadOnlySpan<byte> password)` to `Argon2` class
- [ ] Add public `bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<byte> hash)` 
- [ ] Ensure existing `void Hash(ReadOnlySpan<byte> password, Span<byte> output)` is public and documented
- [ ] Add string convenience overloads: `Hash(string)`, `Verify(string, ReadOnlySpan<byte>)`
- [ ] Mark old `byte[]` overloads with `[Obsolete("Use Span<byte> overload instead", false)]`
- [ ] Update XML documentation with migration hints
- [ ] Unit tests: all new overload combinations, string vs. span equivalence
- [ ] **PR Review:** API surface verification

**Success Criteria:**
- Span-based API is primary documented API
- Backward-compatible with v2.x byte[] code (with deprecation warnings)

---

### Task 1.3: Update PHC Format API
- [ ] Refactor `Argon2PhcFormat.Encode()` to accept immutable `Argon2Parameters`
- [ ] Add new methods:
  - `string HashToPhcString(string password, Argon2Parameters parameters)`
  - `(bool IsValid, Argon2Parameters? Params) VerifyPhcString(string password, string phcString)`
- [ ] Update tuple-based `HashPasswordWithSalt()` to return `(byte[] Hash, byte[] Salt)`
- [ ] Mark old static `HashPassword()` with `[Obsolete]`
- [ ] Unit tests: PHC encoding/decoding, tuple returns, parameter recovery
- [ ] **PR Review:** API consistency check

**Success Criteria:**
- PHC format methods work with immutable parameters
- Tuples eliminate ambiguous out parameters

---

### Task 1.4: XML Documentation & Comments
- [ ] Add or update XML comments for all public members in `Argon2.cs`
- [ ] Add or update XML comments for `Argon2Parameters` (all properties)
- [ ] Add or update XML comments for `Argon2PhcFormat` (all public methods)
- [ ] Include `<remarks>`, `<exception>`, and `<example>` tags where helpful
- [ ] Generate and verify `.xml` documentation file in output
- [ ] **PR Review:** Documentation quality check

**Success Criteria:**
- IntelliSense documentation is clear and helpful
- No public members lack XML comments

---

## Phase 2: Performance Optimizations (Weeks 3-4)

### Task 2.1: Replace BitConverter with BinaryPrimitives
- [ ] In `Argon2Core.BytesToQwords()`: Replace `BitConverter.ToUInt64()` with `BinaryPrimitives.ReadUInt64LittleEndian()`
- [ ] In `Argon2Core.QwordsToBytes()`: Replace `BitConverter.TryWriteBytes()` with `BinaryPrimitives.WriteUInt64LittleEndian()`
- [ ] In `Blake2b.LoadMessage()`: Use `BinaryPrimitives.ReadUInt64LittleEndian()`
- [ ] In `Blake2b.Compress()` result write: Use `BinaryPrimitives.WriteUInt64LittleEndian()`
- [ ] Verify System.Buffers.Binary namespace is referenced
- [ ] Unit tests: Verify hash outputs unchanged (determinism test)
- [ ] Benchmark: Measure throughput improvement (before/after)
- [ ] **PR Review:** Code performance validation

**Success Criteria:**
- All unit tests pass with identical hash outputs
- Measured 5-15% throughput improvement

---

### Task 2.2: MemoryMarshal Span Casting
- [ ] In `Argon2Core.BytesToQwords()`: Explore `MemoryMarshal.Cast<byte, ulong>()` for zero-copy conversion
- [ ] In `Argon2Core.QwordsToBytes()`: Explore `MemoryMarshal.Cast<ulong, byte>()` for zero-copy conversion
- [ ] Document endianness assumptions and platform-specific notes
- [ ] Fallback to manual loop if alignment isn't guaranteed
- [ ] Unit tests: Verify hash outputs identical, test on multiple platforms if possible
- [ ] Benchmark: Measure throughput gain (before/after)
- [ ] **PR Review:** Platform compatibility check

**Success Criteria:**
- No alignment-related exceptions in production
- 10-20% improvement in block filling operations

---

### Task 2.3: Implement Parallel Lane Processing
- [ ] Add optional `MaxParallelism` property to `Argon2Parameters` (default: `Parallelism` value)
- [ ] Modify `Argon2Engine.FillMemoryBlocks()` to use `Parallel.For()` for lane iteration
- [ ] Set `ParallelOptions.MaxDegreeOfParallelism` based on configuration
- [ ] Ensure thread-safe memory buffer access (using slices/ranges, no race conditions)
- [ ] Unit tests: Parallelization off, reduced parallelism, full parallelism; verify deterministic results
- [ ] Benchmark: Measure speedup on multi-core hardware (1 core vs. 4 cores vs. 8 cores)
- [ ] **PR Review:** Concurrency & correctness review

**Success Criteria:**
- Parallel execution produces identical results to serial
- Measured 2x-4x speedup on multi-core systems
- No race conditions or data corruption

---

### Task 2.4: Enhanced Buffer Cleanup & ArrayPool
- [ ] In `Argon2Engine.Hash()`: Ensure `finally` block calls `CryptographicOperations.ZeroMemory()` on memory buffer
- [ ] Call `ArrayPool<ulong>.Shared.Return(memory, clearBuffer: true)` to auto-clear on return (or manual clear)
- [ ] Review all stack buffers in `Blake2b` and `Argon2Core` for sensitive data
- [ ] Add `[DebuggerBrowsable(DebuggerBrowsableState.Never)]` to public fields if any (optional)
- [ ] Unit tests: Verify buffer is zeroized post-operation (if testable)
- [ ] Document security best practices in public API comments
- [ ] **PR Review:** Security audit

**Success Criteria:**
- All sensitive buffers cleared before deallocation
- No measurable performance regression

---

## Phase 3: Testing & Quality (Weeks 5-6)

### Task 3.1: Expand RFC 9106 Test Vectors
- [ ] Obtain RFC 9106 official test vectors (hex format)
- [ ] Create new test class: `Argon2Rfc9106OfficialVectorsTests`
- [ ] Implement test methods for each official vector (Argon2d, i, id with known params)
- [ ] Verify computed hash matches expected hex output exactly
- [ ] Document test vector source and reference
- [ ] Unit tests: All three variants, edge cases (minimum params, maximum hash length)
- [ ] **PR Review:** Test vector validation

**Success Criteria:**
- All RFC 9106 official vectors pass
- Test vectors documented with source

---

### Task 3.2: Edge Case & Boundary Tests
- [ ] Create test class: `Argon2EdgeCaseTests`
- [ ] Test: Empty password, very long password (1MB+)
- [ ] Test: Minimum salt (8 bytes), maximum salt
- [ ] Test: Minimum parameters (8 KB, 1 iteration, 1 parallelism)
- [ ] Test: Large hash output (256+ bytes)
- [ ] Test: Reference block addressing boundary conditions
- [ ] Test: Parallelism with varying lane counts (1, 2, 4, 8)
- [ ] **PR Review:** Boundary condition validation

**Success Criteria:**
- All edge cases handled correctly
- No crashes or unexpected behavior

---

### Task 3.3: Reference Block Addressing Tests
- [ ] Create test class: `Argon2ReferenceBlockAddressingTests`
- [ ] Add focused tests for `CalculateRefAreaSize()` boundary cases
- [ ] Add tests for `GetRefBlockIndexDataIndependent()` and `GetRefBlockIndexDataDependent()`
- [ ] Verify addressing is within bounds for all iterations/slices
- [ ] Verify addressing differs between Argon2d/i/id as expected
- [ ] **PR Review:** Algorithm correctness validation

**Success Criteria:**
- Reference addressing logic verified comprehensively
- No out-of-bounds access in any scenario

---

### Task 3.4: BenchmarkDotNet Suite
- [ ] Create new project: `test/Argon2Sharp.Benchmarks/`
- [ ] Add csproj with BenchmarkDotNet NuGet package
- [ ] Implement benchmark class: `Argon2HashingBenchmarks`
  - Parameterized: MemorySizeKB (32, 65536), Parallelism (1, 4), Type (Argon2d/i/id)
  - Benchmark method: `Hash("password")` with configured parameters
- [ ] Run benchmarks locally: capture baseline (v2.x) and v3.0
- [ ] Generate summary report (Markdown) with throughput/memory comparisons
- [ ] Document setup instructions (warm-up count, iteration count)
- [ ] **PR Review:** Performance baseline validation

**Success Criteria:**
- Benchmarks compile and run without errors
- Baseline metrics documented (v3.0 vs. v2.x)
---

## Phase 4: Documentation & Polish (Weeks 7-8)

### Task 4.1: Update README.md
- [ ] Add/update sections:
  - **Features:** List v3.0 improvements (parallelization, Span API, etc.)
  - **Recommended Parameters:** Table with scenarios (web, desktop, CLI)
  - **Performance:** Benchmark results and comparison
  - **Breaking Changes (v3.0):** Link to SPECIFICATION_v3.0.md
  - **Migration Guide:** Link to MIGRATION_v2_to_v3.md
  - **Examples:** Update code snippets to use Span API
  - **Security:** Best practices for sensitive data handling
- [ ] Ensure examples use modern API and are copy-pasteable
- [ ] Test all examples compile
- [ ] **PR Review:** Documentation clarity check

**Success Criteria:**
- README reflects v3.0 features and API
- Examples are up-to-date and working

---

### Task 4.3: CHANGELOG.md
- [ ] Create/update `CHANGELOG.md` in root directory (if not present)
- [ ] Follow "Keep a Changelog" format
- [ ] Add `## [3.0.0]` section:
  - Breaking Changes (list all)
  - Added (new features)
  - Changed (modifications)
  - Fixed (bug fixes)
  - Deprecated (old API marked obsolete)
  - Removed (if any)
- [ ] Include migration reference
- [ ] Keep previous version entries for context
- [ ] **PR Review:** Changelog accuracy check

**Success Criteria:**
- CHANGELOG is comprehensive and clear
- All breaking changes documented

---

## Phase 5: Release Preparation (Weeks 9-10)

### Task 5.1: Release Candidate (RC1) Build
- [ ] Bump version to `3.0.0-rc.1` in `Directory.Build.props`
- [ ] Build NuGet package in Release config: `dotnet pack -c Release`
- [ ] Verify package contents (dll, xml docs, symbols if applicable)
- [ ] Test package locally: `dotnet add package Argon2Sharp --version 3.0.0-rc.1 --source <local>`
- [ ] Publish RC1 to NuGet.org (pre-release flag)
- [ ] Announce RC1 to community (GitHub discussions, email, docs)
- [ ] **PR Review:** Package quality check

**Success Criteria:**
- RC1 package builds successfully and installs correctly
- Public announcement made
---

### Task 5.2: Final Release Build & Publishing
- [ ] Verify `Directory.Build.props` version is `3.0.0`
- [ ] Build package: `dotnet pack -c Release`
- [ ] Generate release notes (finalize `RELEASE_NOTES_v3.0.md`)
- [ ] Publish to NuGet.org (full release, not pre-release)
- [ ] Create GitHub Release with:
  - Tag: `v3.0.0`
  - Release notes (from RELEASE_NOTES_v3.0.md)
  - Link to migration guide
  - Built artifacts (optional: nuget package, symbols)
- [ ] Verify NuGet package is discoverable & installable
- [ ] **PR Review:** Release artifacts validation

**Success Criteria:**
- NuGet package published and visible
- GitHub Release created
- All artifacts in place

---

## Cross-Cutting Tasks

### Documentation Status Tracker

| Document | Status | Owner | Target Date |
|----------|--------|-------|-------------|
| SPECIFICATION_v3.0.md | ✅ Draft Complete | - | 2025-11-12 |
| README.md Updates | ⏳ Pending | - | Week 8 |
| API XML Comments | ⏳ Pending | - | Week 2 |
| Benchmark Report | ⏳ Pending | - | Week 6 |

---

## Risk Mitigation Checklist

- [ ] **Breaking Changes Communication:** Announce v3.0 early, provide clear migration guide
- [ ] **Regression Testing:** Run full test suite after each phase; keep v2.x tests passing
- [ ] **Platform Compatibility:** Test on Windows, Linux, macOS if possible
- [ ] **Performance Validation:** Benchmark before/after each optimization; document trade-offs
- [ ] **Security Review:** Code review all memory zeroization and buffer cleanup code
- [ ] **Backward Compatibility:** Keep deprecated v2.x methods functional (warn but don't break)

---

## Sign-Off Criteria

- [ ] All tests passing (≥85% coverage)
- [ ] All benchmarks published with metrics
- [ ] Documentation complete & reviewed
- [ ] Migration guide clear & actionable
- [ ] CI/CD pipeline operational
- [ ] Final release artifacts ready

---

**Document Version:** 1.0  
**Last Updated:** 2025-11-12  
**Next Review:** 2025-11-26

