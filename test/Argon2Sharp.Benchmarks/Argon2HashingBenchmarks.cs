using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

namespace Argon2Sharp.Benchmarks;

/// <summary>
/// Benchmarks for Argon2 hashing operations.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class Argon2HashingBenchmarks
{
    private byte[] _salt = null!;
    private byte[] _password = null!;
    private Argon2Parameters _testParams = null!;
    private Argon2Parameters _defaultParams = null!;
    private Argon2Parameters _highSecurityParams = null!;

    [GlobalSetup]
    public void Setup()
    {
        _salt = Argon2.GenerateSalt(16);
        _password = "MySecurePassword123!"u8.ToArray();
        
        _testParams = Argon2Parameters.CreateForTesting() with { Salt = _salt };
        _defaultParams = Argon2Parameters.CreateDefault() with { Salt = _salt };
        _highSecurityParams = Argon2Parameters.CreateHighSecurity() with { Salt = _salt };
    }

    [Benchmark(Baseline = true)]
    public byte[] Hash_TestParameters()
    {
        var argon2 = new Argon2(_testParams);
        return argon2.Hash(_password.AsSpan());
    }

    [Benchmark]
    public byte[] Hash_DefaultParameters()
    {
        var argon2 = new Argon2(_defaultParams);
        return argon2.Hash(_password.AsSpan());
    }

    [Benchmark]
    public byte[] Hash_HighSecurityParameters()
    {
        var argon2 = new Argon2(_highSecurityParams);
        return argon2.Hash(_password.AsSpan());
    }

    [Benchmark]
    public string HashToPhcString_Default()
    {
        return Argon2PhcFormat.HashToPhcString("password", _defaultParams);
    }

    [Benchmark]
    public bool Verify_TestParameters()
    {
        var argon2 = new Argon2(_testParams);
        byte[] hash = argon2.Hash(_password.AsSpan());
        return argon2.Verify(_password.AsSpan(), hash.AsSpan());
    }
}

/// <summary>
/// Benchmarks comparing different memory sizes.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class Argon2MemorySizeBenchmarks
{
    private byte[] _salt = null!;
    private const string Password = "password";

    [GlobalSetup]
    public void Setup()
    {
        _salt = Argon2.GenerateSalt(16);
    }

    [Benchmark]
    [Arguments(32)]      // 32 KB
    [Arguments(1024)]    // 1 MB
    [Arguments(4096)]    // 4 MB
    [Arguments(19456)]   // 19 MB (default)
    public byte[] Hash_VariableMemory(int memorySizeKB)
    {
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = memorySizeKB,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = _salt
        };
        
        var argon2 = new Argon2(parameters);
        return argon2.Hash(Password);
    }
}

/// <summary>
/// Benchmarks comparing different iteration counts.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class Argon2IterationBenchmarks
{
    private byte[] _salt = null!;
    private const string Password = "password";

    [GlobalSetup]
    public void Setup()
    {
        _salt = Argon2.GenerateSalt(16);
    }

    [Benchmark]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public byte[] Hash_VariableIterations(int iterations)
    {
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 1024, // 1 MB for faster benchmarks
            Iterations = iterations,
            Parallelism = 1,
            HashLength = 32,
            Salt = _salt
        };
        
        var argon2 = new Argon2(parameters);
        return argon2.Hash(Password);
    }
}
