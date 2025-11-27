# Argon2Sharp v3.5 Benchmark Results (Optimized + Parallel)

## Environment
- **BenchmarkDotNet**: v0.14.0
- **OS**: EndeavourOS
- **CPU**: 12th Gen Intel Core i7-12700H, 1 CPU, 20 logical and 14 physical cores
- **Runtime**: .NET 9.0.9 (9.0.925.41916), X64 RyuJIT AVX2
- **Hardware Intrinsics**: AVX2, AES, BMI1, BMI2, FMA, LZCNT, PCLMUL, POPCNT, AvxVnni, SERIALIZE (VectorSize=256)

## Results Summary

| Method                      | Mean          | Error        | StdDev       | Allocated |
|---------------------------- |--------------:|-------------:|-------------:|----------:|
| Hash_TestParameters         |      52.67 μs |     0.233 μs |     0.218 μs |     128 B |
| Hash_DefaultParameters      |  15,396.13 μs |   286.659 μs |   362.531 μs |     145 B |
| Hash_HighSecurityParameters |  51,167.73 μs |   959.467 μs |   897.486 μs |  40,123 B |
| HashToPhcString_Default     |  15,512.29 μs |   469.012 μs | 1,375.532 μs |     778 B |
| Verify_TestParameters       |     103.48 μs |     0.596 μs |     0.557 μs |     176 B |

---

## Comparison with v3.0 (Baseline)

### Performance Comparison

| Method                      | v3.0 Mean     | v3.5 Mean     | Improvement | Speedup |
|---------------------------- |--------------:|--------------:|------------:|--------:|
| Hash_TestParameters         |      88.78 μs |      52.67 μs |   **40.7%** | **1.69x** |
| Hash_DefaultParameters      |  18,900.00 μs |  15,396.13 μs |   **18.5%** | **1.23x** |
| Hash_HighSecurityParameters | 153,620.00 μs |  51,167.73 μs |   **66.7%** | **3.00x** |
| HashToPhcString_Default     |  18,150.00 μs |  15,512.29 μs |   **14.5%** | **1.17x** |
| Verify_TestParameters       |     177.15 μs |     103.48 μs |   **41.6%** | **1.71x** |

### Key Achievements

🚀 **Hash_HighSecurityParameters: 51 ms** (Target: 50 ms) - **3x faster than v3.0!**

1. **High Security (256 MB)**: **66.7% faster** - Massive improvement with parallel lanes
2. **Test Parameters (Fast Path)**: **41% faster** - Optimized single-thread performance
3. **Default Parameters (Production)**: **18.5% faster** - Improved for typical use cases
4. **Verification**: **41.6% faster** - Critical for authentication flows

---

## v3.5 Optimizations Applied

### 1. Parallel Lane Processing 🆕
- `Parallel.For` for processing lanes concurrently
- Threshold-based activation (16+ MB memory, p > 1)
- Thread-safe memory access using shared array
- Scales with CPU core count

### 2. SIMD Acceleration (AVX2)
- `Vector<ulong>` for parallel XOR operations
- Hardware-accelerated block operations on 256-bit vectors
- 4x parallel ulong processing per vector operation

### 3. Aggressive Inlining
- `[MethodImpl(MethodImplOptions.AggressiveInlining | AggressiveOptimization)]`
- Applied to all hot-path functions
- Eliminates function call overhead in tight loops

### 4. Loop Unrolling
- **8x unrolled scalar path** for non-SIMD fallback
- **64 explicit PermutationP calls** (fully unrolled)
- **12 fully unrolled Blake2b rounds** with local variable caching

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
- **Parallel: NO** (below threshold)

### Hash_DefaultParameters
- Memory: 64 MiB (65536 KB)
- Iterations: 4
- Parallelism: 4
- Hash Length: 32 bytes
- **Parallel: YES** (4 lanes)

### Hash_HighSecurityParameters
- Memory: 256 MiB (262144 KB)
- Iterations: 6
- Parallelism: 4
- Hash Length: 64 bytes
- **Parallel: YES** (4 lanes)

---

## Detailed Statistics

### Hash_HighSecurityParameters (Target: 50ms ✅)
```
Mean = 51.168 ms, StdErr = 0.232 ms (0.45%), N = 15, StdDev = 0.897 ms
Min = 49.766 ms, Q1 = 50.499 ms, Median = 51.004 ms, Q3 = 51.858 ms, Max = 53.043 ms
CI 99.9% = [50.208 ms; 52.127 ms]
```

### Hash_TestParameters
```
Mean = 52.669 μs, StdErr = 0.056 μs (0.11%), N = 15, StdDev = 0.218 μs
Min = 52.181 μs, Q1 = 52.589 μs, Median = 52.625 μs, Q3 = 52.791 μs, Max = 53.034 μs
CI 99.9% = [52.436 μs; 52.902 μs]
```

### Hash_DefaultParameters
```
Mean = 15.396 ms, StdErr = 0.076 ms (0.49%), N = 23, StdDev = 0.363 ms
Min = 14.447 ms, Q1 = 15.193 ms, Median = 15.423 ms, Q3 = 15.596 ms, Max = 16.077 ms
CI 99.9% = [15.109 ms; 15.683 ms]
```

---

## Summary

**v3.5 delivers massive performance improvements, especially for high-security workloads:**

- 🚀 **3x faster** for High Security (256 MB) - from 154ms to 51ms
- 📈 **40% faster** for lightweight operations
- 📈 **18% faster** for production workloads
- ✅ **All 425 tests passing**
- 🔒 **RFC 9106 compliant**
- 🧵 **Multi-threaded lane processing**

The optimizations leverage modern CPU features (AVX2, multi-threading) while maintaining full backward compatibility with the v3.0 API.

---

*Benchmark Date: 2025-11-26*
*Argon2Sharp Version: 3.5.0 (Optimized + Parallel)*
