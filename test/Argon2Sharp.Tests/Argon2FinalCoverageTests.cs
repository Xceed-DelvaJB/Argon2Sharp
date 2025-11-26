using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Final batch of specific tests to ensure complete coverage of edge cases,
/// API consistency, and cryptographic properties.
/// </summary>
public class Argon2FinalCoverageTests
{
    #region Cryptographic Property Tests

    [Fact]
    public void TestHash_PreimageResistance_CannotReverseHash()
    {
        // Arrange - hash should be one-way function
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        string password = "secretpassword";
        byte[] hash = argon2.Hash(password);

        // Assert - hash should not contain password bytes
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        bool containsPassword = ContainsSequence(hash, passwordBytes);
        Assert.False(containsPassword, "Hash should not contain original password bytes");
    }

    [Fact]
    public void TestHash_SecondPreimageResistance_DifferentPasswordsSameSalt()
    {
        // Arrange - different passwords should not collide
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Generate many password hashes
        var hashes = new HashSet<string>();
        for (int i = 0; i < 500; i++)
        {
            byte[] hash = argon2.Hash($"password{i}_{Guid.NewGuid()}");
            hashes.Add(Convert.ToBase64String(hash));
        }

        // Assert - no collisions
        Assert.Equal(500, hashes.Count);
    }

    [Fact]
    public void TestHash_OutputDistribution_NoPatterns()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act - hash and analyze byte distribution
        byte[] hash = argon2.Hash("analyzepattern");
        
        // Count occurrences of each byte value
        var byteCounts = new int[256];
        foreach (var b in hash)
            byteCounts[b]++;

        // Assert - no single byte should dominate (reasonable distribution)
        int maxCount = byteCounts.Max();
        Assert.True(maxCount <= hash.Length / 2, "Hash output should have reasonable byte distribution");
    }

    #endregion

    #region Specific Parameter Combination Tests

    [Fact]
    public void TestHash_HighMemory_LowIterations()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 2048, // 2 MB
            Iterations = 1,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestHash_LowMemory_HighIterations()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 8, // Minimum
            Iterations = 10,   // High iterations
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestHash_MaxParallelismMinMemory()
    {
        // Arrange - memory must be at least 8 * parallelism
        int parallelism = 32;
        int minMemory = 8 * parallelism;
        byte[] salt = Argon2.GenerateSalt(16);

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = minMemory,
            Iterations = 1,
            Parallelism = parallelism,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    #endregion

    #region Verification Edge Cases

    [Fact]
    public void TestVerify_CaseSensitivity()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        string password = "Password123";
        byte[] hash = argon2.Hash(password);

        // Act & Assert - verification should be case-sensitive
        Assert.True(argon2.Verify("Password123", hash.AsSpan()));
        Assert.False(argon2.Verify("password123", hash.AsSpan()));
        Assert.False(argon2.Verify("PASSWORD123", hash.AsSpan()));
        Assert.False(argon2.Verify("PaSsWoRd123", hash.AsSpan()));
    }

    [Fact]
    public void TestVerify_WhitespaceSensitivity()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        string password = "password";
        byte[] hash = argon2.Hash(password);

        // Act & Assert - whitespace should be significant
        Assert.True(argon2.Verify("password", hash.AsSpan()));
        Assert.False(argon2.Verify(" password", hash.AsSpan()));
        Assert.False(argon2.Verify("password ", hash.AsSpan()));
        Assert.False(argon2.Verify("pass word", hash.AsSpan()));
        Assert.False(argon2.Verify("password\t", hash.AsSpan()));
        Assert.False(argon2.Verify("password\n", hash.AsSpan()));
    }

    #endregion

    #region PHC Format Edge Cases

    [Fact]
    public void TestPhcFormat_EncodeWithExtremeParameters()
    {
        // Arrange
        byte[] hash = new byte[512]; // Large hash
        byte[] salt = new byte[64];  // Large salt
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 1048576, 100, 64);

        // Assert
        Assert.Contains("m=1048576", encoded);
        Assert.Contains("t=100", encoded);
        Assert.Contains("p=64", encoded);
    }

    [Fact]
    public void TestPhcFormat_DecodeWithExtremeParameters()
    {
        // Arrange
        byte[] hash = new byte[512];
        byte[] salt = new byte[64];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);
        
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 1048576, 100, 64);

        // Act
        bool success = Argon2PhcFormat.TryDecode(encoded, out byte[]? decodedHash, out byte[]? decodedSalt,
            out _, out int m, out int t, out int p, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(hash, decodedHash);
        Assert.Equal(salt, decodedSalt);
        Assert.Equal(1048576, m);
        Assert.Equal(100, t);
        Assert.Equal(64, p);
    }

    #endregion

    #region Instance Reuse Tests

    [Fact]
    public void TestArgon2Instance_ReuseForMultiplePasswords()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act - hash multiple different passwords with same instance
        var results = new Dictionary<string, (byte[] hash, bool verified)>();
        for (int i = 0; i < 20; i++)
        {
            string password = $"password_{i}";
            byte[] hash = argon2.Hash(password);
            bool verified = argon2.Verify(password, hash.AsSpan());
            results[password] = (hash, verified);
        }

        // Assert - all should succeed
        Assert.All(results.Values, r => Assert.True(r.verified));
        
        // All hashes should be different
        var uniqueHashes = results.Values.Select(r => Convert.ToBase64String(r.hash)).Distinct().Count();
        Assert.Equal(20, uniqueHashes);
    }

    #endregion

    #region Helper Methods

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }

    #endregion
}
