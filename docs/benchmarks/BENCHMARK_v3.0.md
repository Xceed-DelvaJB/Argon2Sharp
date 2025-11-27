# Argon2Sharp v3.0 Benchmark Results

**Date:** November 26, 2025  
**Version:** 3.0.0

## System Information

- **OS:** EndeavourOS (Linux)
- **CPU:** 12th Gen Intel Core i7-12700H, 1 CPU, 20 logical and 14 physical cores
- **Runtime:** .NET 9.0.9 (9.0.925.41916), X64 RyuJIT AVX2
- **.NET SDK:** 9.0.110
- **BenchmarkDotNet:** v0.14.0

## Argon2HashingBenchmarks

| Method                      | Mean          | Error        | StdDev       | Ratio    | RatioSD | Allocated | Alloc Ratio |
|---------------------------- |--------------:|-------------:|-------------:|---------:|--------:|----------:|------------:|
| Hash_TestParameters         |      88.78 μs |     0.862 μs |     0.764 μs |     1.00 |    0.01 |     128 B |        1.00 |
| Hash_DefaultParameters      |  18,896.14 μs |   374.279 μs |   499.651 μs |   212.85 |    5.80 |     162 B |        1.27 |
| Hash_HighSecurityParameters | 153,619.43 μs | 2,773.852 μs | 3,406.540 μs | 1,730.43 |   40.22 |     396 B |        3.09 |
| HashToPhcString_Default     |  18,692.43 μs |   367.908 μs |   377.815 μs |   210.56 |    4.49 |     778 B |        6.08 |
| Verify_TestParameters       |     178.12 μs |     1.242 μs |     1.037 μs |     2.01 |    0.02 |     176 B |        1.38 |

## Parameter Configurations

### Test Parameters (Baseline)
- **Memory:** 32 KB
- **Iterations:** 2
- **Parallelism:** 1
- **Hash Length:** 32 bytes

### Default Parameters
- **Memory:** 19,456 KB (~19 MB)
- **Iterations:** 2
- **Parallelism:** 1
- **Hash Length:** 32 bytes

### High Security Parameters
- **Memory:** 65,536 KB (64 MB)
- **Iterations:** 4
- **Parallelism:** 4
- **Hash Length:** 32 bytes

## Analysis

- **Hash_TestParameters** is the baseline with minimal memory (32 KB), completing in ~89 μs
- **Hash_DefaultParameters** uses ~19 MB of memory, taking ~18.9 ms (213x slower than test parameters)
- **Hash_HighSecurityParameters** uses 64 MB with 4 iterations, taking ~154 ms (1730x slower than test parameters)
- **Verify_TestParameters** performs hash + comparison, taking ~178 μs (2x the hash time as expected)
- Memory allocation is very efficient, with minimal allocations across all operations

## Notes

- These benchmarks were run on a high-performance laptop CPU
- Results will vary based on hardware, especially for memory-intensive operations
- The `Hash_DefaultParameters` configuration is suitable for most password hashing use cases
- The `Hash_HighSecurityParameters` configuration provides maximum security for high-value targets
