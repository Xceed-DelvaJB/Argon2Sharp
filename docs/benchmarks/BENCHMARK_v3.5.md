# Argon2Sharp v3.5 Benchmark Results (Optimized)

## Environment
- **BenchmarkDotNet**: v0.14.0
- **OS**: EndeavourOS
- **CPU**: 12th Gen Intel Core i7-12700H, 1 CPU, 20 logical and 14 physical cores
- **Runtime**: .NET 9.0.9 (9.0.925.41916), X64 RyuJIT AVX2
- **Hardware Intrinsics**: AVX2, AES, BMI1, BMI2, FMA, LZCNT, PCLMUL, POPCNT, AvxVnni, SERIALIZE (VectorSize=256)

## Results Summary

| Method                      | Mean          | Error        | StdDev       | Allocated |
|---------------------------- |--------------:|-------------:|-------------:|----------:|
| Hash_TestParameters         |      52.29 μs |     0.212 μs |     0.188 μs |     128 B |
| Hash_DefaultParameters      |  16,174.92 μs |   319.533 μs |   328.137 μs |     162 B |
| Hash_HighSecurityParameters | 127,385.22 μs | 1,341.497 μs | 1,189.202 μs |     396 B |
| HashToPhcString_Default     |  15,533.36 μs |   295.837 μs |   276.726 μs |     778 B |
| Verify_TestParameters       |     103.82 μs |     0.522 μs |     0.489 μs |     176 B |

---

## Comparison with v3.0 (Baseline)

### Performance Comparison

| Method                      | v3.0 Mean     | v3.5 Mean     | Improvement | Speedup |
|---------------------------- |--------------:|--------------:|------------:|--------:|
| Hash_TestParameters         |      88.78 μs |      52.29 μs |   **41.1%** | **1.70x** |
| Hash_DefaultParameters      |  18,900.00 μs |  16,174.92 μs |   **14.4%** | **1.17x** |
| Hash_HighSecurityParameters | 153,620.00 μs | 127,385.22 μs |   **17.1%** | **1.21x** |
| HashToPhcString_Default     |  18,150.00 μs |  15,533.36 μs |   **14.4%** | **1.17x** |
| Verify_TestParameters       |     177.15 μs |     103.82 μs |   **41.4%** | **1.71x** |

### Key Insights

1. **Test Parameters (Fast Path)**: **41% faster** - Massive improvement in lightweight operations
2. **Default Parameters (Production)**: **14% faster** - Significant improvement for typical use cases
3. **High Security**: **17% faster** - Better performance for high-memory operations
4. **PHC String Generation**: **14% faster** - Improved encoding/decoding
5. **Verification**: **41% faster** - Critical for authentication flows

---

## v3.5 Optimizations Applied

### 1. SIMD Acceleration (AVX2)
- `FillBlockSimd()` using `Vector<ulong>` for parallel XOR operations
- Hardware-accelerated block operations on 256-bit vectors
- 4x parallel ulong processing per vector operation

### 2. Aggressive Inlining
- `[MethodImpl(MethodImplOptions.AggressiveInlining | AggressiveOptimization)]`
- Applied to all hot-path functions: `CompressionG`, `CompressionGB`, `PermutationP`, `GInline`
- Eliminates function call overhead in tight loops

### 3. Loop Unrolling
- **8x unrolled scalar path** for non-SIMD fallback
- **64 explicit PermutationP calls** (fully unrolled)
- **12 fully unrolled Blake2b rounds** with local variable caching

### 4. Register Optimization
- Local variable caching (`v0-v15`, `m0-m15`) for Blake2b state
- Pre-computed constants (`_isArgon2i`, `_isArgon2id`)
- Eliminated array indexing in hot paths

### 5. Hardware Intrinsics
- `ulong.RotateRight()` intrinsic (compiles to single CPU instruction)
- Fused multiply-add patterns for GB function
- Reference parameters (`ref`) in G function to avoid copies

---

## Benchmark Test Parameters

### Hash_TestParameters
- Memory: 1 MiB (1024 KB)
- Iterations: 1
- Parallelism: 1
- Hash Length: 32 bytes

### Hash_DefaultParameters
- Memory: 64 MiB (65536 KB)
- Iterations: 4
- Parallelism: 4
- Hash Length: 32 bytes

### Hash_HighSecurityParameters
- Memory: 256 MiB (262144 KB)
- Iterations: 6
- Parallelism: 4
- Hash Length: 64 bytes

---

## Detailed Statistics

### Hash_TestParameters
```
Mean = 52.286 μs, StdErr = 0.050 μs (0.10%), N = 14, StdDev = 0.188 μs
Min = 52.046 μs, Q1 = 52.136 μs, Median = 52.249 μs, Q3 = 52.449 μs, Max = 52.607 μs
CI 99.9% = [52.074 μs; 52.498 μs]
```

### Hash_DefaultParameters
```
Mean = 16.175 ms, StdErr = 0.080 ms (0.49%), N = 17, StdDev = 0.328 ms
Min = 15.778 ms, Q1 = 15.914 ms, Median = 16.108 ms, Q3 = 16.316 ms, Max = 16.734 ms
CI 99.9% = [15.855 ms; 16.494 ms]
```

### Hash_HighSecurityParameters
```
Mean = 127.385 ms, StdErr = 0.318 ms (0.25%), N = 14, StdDev = 1.189 ms
Min = 125.080 ms, Q1 = 127.166 ms, Median = 127.491 ms, Q3 = 128.188 ms, Max = 129.190 ms
CI 99.9% = [126.044 ms; 128.727 ms]
```

### HashToPhcString_Default
```
Mean = 15.533 ms, StdErr = 0.071 ms (0.46%), N = 15, StdDev = 0.277 ms
Min = 15.061 ms, Q1 = 15.383 ms, Median = 15.525 ms, Q3 = 15.638 ms, Max = 16.052 ms
CI 99.9% = [15.238 ms; 15.829 ms]
```

### Verify_TestParameters
```
Mean = 103.818 μs, StdErr = 0.126 μs (0.12%), N = 15, StdDev = 0.489 μs
Min = 102.788 μs, Q1 = 103.532 μs, Median = 103.787 μs, Q3 = 104.090 μs, Max = 104.718 μs
CI 99.9% = [103.296 μs; 104.340 μs]
```

---

## Summary

**v3.5 delivers significant performance improvements across all benchmarks:**

- 🚀 **Up to 41% faster** for lightweight operations
- 📈 **14-17% faster** for production workloads
- ✅ **All 425 tests passing**
- 🔒 **RFC 9106 compliant**
- 💾 **Zero-allocation hot paths maintained**

The optimizations leverage modern CPU features (AVX2, hardware rotate) while maintaining full backward compatibility with the v3.0 API.

---

*Benchmark Date: 2025-11-26*
*Argon2Sharp Version: 3.5.0 (Optimized)*
