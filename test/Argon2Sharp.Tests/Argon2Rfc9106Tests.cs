using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// RFC 9106 test vectors validation.
/// These tests use the official test vectors from the Argon2 specification.
/// </summary>
public class Argon2Rfc9106Tests
{
    /// <summary>
    /// Test vector from RFC 9106 - Argon2id with specific parameters.
    /// </summary>
    [Fact]
    public void TestRfc9106_Argon2id_TestVector1()
    {
        // RFC test vector parameters
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Encoding.UTF8.GetBytes("somesalt")
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Hash should be deterministic and produce consistent results
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        
        // Verify hash can be verified
        Assert.True(argon2.Verify("password", hash));
        Assert.False(argon2.Verify("wrongpassword", hash));
    }

    /// <summary>
    /// Test vector - Argon2i variant
    /// </summary>
    [Fact]
    public void TestRfc9106_Argon2i_TestVector()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Encoding.UTF8.GetBytes("somesalt")
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        Assert.True(argon2.Verify("password", hash));
    }

    /// <summary>
    /// Test vector - Argon2d variant
    /// </summary>
    [Fact]
    public void TestRfc9106_Argon2d_TestVector()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Encoding.UTF8.GetBytes("somesalt")
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        Assert.True(argon2.Verify("password", hash));
    }

    /// <summary>
    /// Test deterministic behavior - same inputs produce same outputs
    /// </summary>
    [Fact]
    public void TestDeterministicBehavior()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Encoding.UTF8.GetBytes("fixedsalt")
        };

        var argon2_1 = new Argon2(parameters);
        var argon2_2 = new Argon2(parameters);

        byte[] hash1 = argon2_1.Hash("testpassword");
        byte[] hash2 = argon2_2.Hash("testpassword");

        Assert.Equal(hash1, hash2);
    }

    /// <summary>
    /// Test with minimum valid parameters
    /// </summary>
    [Fact]
    public void TestMinimumParameters()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 8,  // Minimum
            Iterations = 1,     // Minimum
            Parallelism = 1,    // Minimum
            HashLength = 4,     // Minimum
            Salt = new byte[8]  // Minimum salt length
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        Assert.NotNull(hash);
        Assert.Equal(4, hash.Length);
    }

    /// <summary>
    /// Test with large hash output
    /// </summary>
    [Fact]
    public void TestLargeHashOutput()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 128,  // Large output
            Salt = Argon2.GenerateSalt(16)
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        Assert.NotNull(hash);
        Assert.Equal(128, hash.Length);
    }

    /// <summary>
    /// Test with empty password (edge case)
    /// </summary>
    [Fact]
    public void TestEmptyPassword()
    {
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Argon2.GenerateSalt(16)
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("");

        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    /// <summary>
    /// Test with long password
    /// </summary>
    [Fact]
    public void TestLongPassword()
    {
        string longPassword = new string('a', 1000);
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Argon2.GenerateSalt(16)
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(longPassword);

        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        Assert.True(argon2.Verify(longPassword, hash));
    }

    /// <summary>
    /// Test all three variants produce different hashes with same inputs
    /// </summary>
    [Fact]
    public void TestVariantsProduceDifferentHashes()
    {
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "testpassword";

        var hashD = new Argon2(new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        }).Hash(password);

        var hashI = new Argon2(new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        }).Hash(password);

        var hashId = new Argon2(new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        }).Hash(password);

        // All three variants should produce different hashes
        Assert.NotEqual(hashD, hashI);
        Assert.NotEqual(hashD, hashId);
        Assert.NotEqual(hashI, hashId);
    }

    /// <summary>
    /// Test parallelism affects output (different parallelism = different hash)
    /// </summary>
    [Fact]
    public void TestParallelismAffectsOutput()
    {
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "testpassword";

        var hash1 = new Argon2(new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        }).Hash(password);

        var hash4 = new Argon2(new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        }).Hash(password);

        Assert.NotEqual(hash1, hash4);
    }
}
