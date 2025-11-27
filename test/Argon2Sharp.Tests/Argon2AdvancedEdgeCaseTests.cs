using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Advanced edge case tests for comprehensive boundary condition coverage.
/// These tests ensure robustness against extreme inputs and unusual scenarios.
/// </summary>
public class Argon2AdvancedEdgeCaseTests
{
    #region Password Boundary Tests

    [Fact]
    public void TestPassword_SingleCharacter()
    {
        // Arrange
        string password = "a";
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password, hash.AsSpan()));
        Assert.False(argon2.Verify("b", hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_SingleByte()
    {
        // Arrange
        byte[] password = [0x00];
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password.AsSpan(), hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_NullByte()
    {
        // Arrange - password containing null byte
        byte[] password = [0x00, 0x01, 0x00, 0x02];
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password.AsSpan(), hash.AsSpan()));
    }

    [Theory]
    [InlineData(100)]
    [InlineData(500)]
    [InlineData(1000)]
    [InlineData(5000)]
    public void TestPassword_VariousLengths(int length)
    {
        // Arrange
        string password = new string('x', length);
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        Assert.True(argon2.Verify(password, hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_AllByteValues()
    {
        // Arrange - password with all possible byte values (0-255)
        byte[] password = new byte[256];
        for (int i = 0; i < 256; i++)
            password[i] = (byte)i;
        
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password.AsSpan(), hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_RepeatedPattern()
    {
        // Arrange - repeating pattern
        byte[] password = new byte[1000];
        for (int i = 0; i < password.Length; i++)
            password[i] = (byte)(i % 16);
        
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password.AsSpan(), hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_HighEntropy()
    {
        // Arrange - high entropy password using random bytes
        byte[] password = Argon2.GenerateSalt(256); // Using GenerateSalt for random bytes
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password.AsSpan(), hash.AsSpan()));
    }

    #endregion

    #region Salt Boundary Tests

    [Theory]
    [InlineData(8)]   // Minimum
    [InlineData(16)]  // Recommended
    [InlineData(32)]  // Extended
    [InlineData(64)]  // Large
    [InlineData(128)] // Very large
    public void TestSalt_VariousLengths(int saltLength)
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(saltLength);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password, hash.AsSpan()));
    }

    [Fact]
    public void TestSalt_AllZeros()
    {
        // Arrange - salt with all zeros (valid but not recommended)
        byte[] salt = new byte[16];
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestSalt_AllOnes()
    {
        // Arrange
        byte[] salt = new byte[16];
        Array.Fill(salt, (byte)0xFF);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestSalt_Sequential()
    {
        // Arrange - sequential salt
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.Length; i++)
            salt[i] = (byte)i;
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestDifferentSalts_ProduceDifferentHashes()
    {
        // Arrange
        string password = "same_password";
        byte[] salt1 = Argon2.GenerateSalt(16);
        byte[] salt2 = Argon2.GenerateSalt(16);
        
        var params1 = Argon2Parameters.CreateForTesting() with { Salt = salt1 };
        var params2 = Argon2Parameters.CreateForTesting() with { Salt = salt2 };

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Hash Length Boundary Tests

    [Theory]
    [InlineData(4)]    // Minimum
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]   // Standard
    [InlineData(64)]   // SHA-512 equivalent
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    public void TestHashLength_Various(int hashLength)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(hashLength)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.Equal(hashLength, hash.Length);
    }

    [Fact]
    public void TestHashLength_LargeOutput1024()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(1024)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.Equal(1024, hash.Length);
        Assert.True(hash.Any(b => b != 0)); // Should have non-zero bytes
    }

    #endregion

    #region Memory Parameter Boundary Tests

    [Theory]
    [InlineData(8)]     // Minimum
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]  // 1 MB
    public void TestMemory_Various(int memorySizeKB)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(memorySizeKB)
            .WithIterations(1)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestMemory_Minimum8KB_WithParallelism1()
    {
        // Arrange - minimum memory with parallelism 1
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(8)
            .WithIterations(1)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestMemory_Minimum64KB_WithParallelism8()
    {
        // Arrange - memory must be at least 8 * parallelism
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(64)  // 8 * 8 = 64
            .WithIterations(1)
            .WithParallelism(8)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    #endregion

    #region Iteration Boundary Tests

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(10)]
    public void TestIterations_Various(int iterations)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(iterations)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestIterations_DifferentIterationsProduceDifferentHashes()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";

        var params1 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(1).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).Build();
        
        var params2 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).Build();

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Parallelism Boundary Tests

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(16)]
    public void TestParallelism_Various(int parallelism)
    {
        // Arrange - memory must be at least 8 * parallelism
        byte[] salt = Argon2.GenerateSalt(16);
        int memorySizeKB = Math.Max(32, 8 * parallelism);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(memorySizeKB)
            .WithIterations(2)
            .WithParallelism(parallelism)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestParallelism_DifferentParallelismProducesDifferentHashes()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";

        var params1 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(64).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).Build();
        
        var params2 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(64).WithIterations(2).WithParallelism(2)
            .WithHashLength(32).WithSalt(salt).Build();

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Secret (Key) Edge Cases

    [Fact]
    public void TestSecret_EmptySecret()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] secret = Array.Empty<byte>();
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .WithSecret(secret)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(256)]
    public void TestSecret_VariousLengths(int secretLength)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] secret = new byte[secretLength];
        new Random(42).NextBytes(secret);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .WithSecret(secret)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify("password", hash.AsSpan()));
    }

    [Fact]
    public void TestSecret_SamePasswordDifferentSecrets()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] secret1 = Encoding.UTF8.GetBytes("secret1");
        byte[] secret2 = Encoding.UTF8.GetBytes("secret2");

        var params1 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).WithSecret(secret1).Build();
        
        var params2 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).WithSecret(secret2).Build();

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Associated Data Edge Cases

    [Fact]
    public void TestAssociatedData_EmptyAD()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] ad = Array.Empty<byte>();
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .WithAssociatedData(ad)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(256)]
    [InlineData(1024)]
    public void TestAssociatedData_VariousLengths(int adLength)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] ad = new byte[adLength];
        new Random(42).NextBytes(ad);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .WithAssociatedData(ad)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestAssociatedData_SamePasswordDifferentAD()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] ad1 = Encoding.UTF8.GetBytes("context1");
        byte[] ad2 = Encoding.UTF8.GetBytes("context2");

        var params1 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).WithAssociatedData(ad1).Build();
        
        var params2 = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32).WithIterations(2).WithParallelism(1)
            .WithHashLength(32).WithSalt(salt).WithAssociatedData(ad2).Build();

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void TestAssociatedData_WithSecretCombined()
    {
        // Arrange - both secret and associated data
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] secret = Encoding.UTF8.GetBytes("mysecret");
        byte[] ad = Encoding.UTF8.GetBytes("mycontext");
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .WithSecret(secret)
            .WithAssociatedData(ad)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify("password", hash.AsSpan()));
    }

    #endregion

    #region Version Tests

    [Theory]
    [InlineData(Argon2Version.Version10)]
    [InlineData(Argon2Version.Version13)]
    public void TestVersion_AllVersions(Argon2Version version)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = version,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify("password", hash.AsSpan()));
    }

    [Fact]
    public void TestVersion_DifferentVersionsProduceDifferentHashes()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";

        var params10 = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version10,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };
        
        var params13 = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var hash10 = new Argon2(params10).Hash(password);
        var hash13 = new Argon2(params13).Hash(password);

        // Assert
        Assert.NotEqual(hash10, hash13);
    }

    #endregion

    #region Combined Parameter Tests

    [Fact]
    public void TestAllMinimumParameters()
    {
        // Arrange - absolute minimum valid parameters
        byte[] salt = new byte[8]; // Minimum salt
        new Random(42).NextBytes(salt);
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 8,     // Minimum
            Iterations = 1,       // Minimum
            Parallelism = 1,      // Minimum
            HashLength = 4,       // Minimum
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("");  // Empty password

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(4, hash.Length);
    }

    [Fact]
    public void TestAllTypesAllVersions()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "test";
        var hashes = new List<byte[]>();

        // Act - test all combinations
        foreach (Argon2Type type in Enum.GetValues<Argon2Type>())
        {
            foreach (Argon2Version version in Enum.GetValues<Argon2Version>())
            {
                var parameters = new Argon2Parameters
                {
                    Type = type,
                    Version = version,
                    MemorySizeKB = 32,
                    Iterations = 2,
                    Parallelism = 1,
                    HashLength = 32,
                    Salt = salt
                };

                var hash = new Argon2(parameters).Hash(password);
                hashes.Add(hash);
            }
        }

        // Assert - all combinations should produce different hashes
        Assert.Equal(6, hashes.Count); // 3 types * 2 versions
        Assert.Equal(hashes.Distinct(new ByteArrayComparer()).Count(), hashes.Count);
    }

    #endregion

    #region Special Character Tests

    [Theory]
    [InlineData("password with spaces")]
    [InlineData("pass\tword\twith\ttabs")]
    [InlineData("pass\nword\nwith\nnewlines")]
    [InlineData("pass\r\nword\r\nwith\r\ncrlf")]
    [InlineData("password\0with\0nulls")]
    [InlineData("🔐🔑🔒🔓💀👻")]
    [InlineData("مرحبا العالم")]
    [InlineData("Привет мир")]
    [InlineData("你好世界")]
    [InlineData("こんにちは世界")]
    [InlineData("🇺🇸🇬🇧🇫🇷🇩🇪🇮🇹")]
    public void TestSpecialCharacterPasswords(string password)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password, hash.AsSpan()));
    }

    [Fact]
    public void TestPassword_LeadingTrailingSpaces()
    {
        // Arrange - spaces should be significant
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        var argon2 = new Argon2(parameters);
        
        // Act
        byte[] hash1 = argon2.Hash("password");
        byte[] hash2 = argon2.Hash(" password");
        byte[] hash3 = argon2.Hash("password ");
        byte[] hash4 = argon2.Hash(" password ");

        // Assert - all should be different
        Assert.NotEqual(hash1, hash2);
        Assert.NotEqual(hash1, hash3);
        Assert.NotEqual(hash1, hash4);
        Assert.NotEqual(hash2, hash3);
    }

    #endregion

    // Helper class for byte array comparison
    private class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? x, byte[]? y)
        {
            if (x == null && y == null) return true;
            if (x == null || y == null) return false;
            return x.SequenceEqual(y);
        }

        public int GetHashCode(byte[] obj)
        {
            return obj.Aggregate(17, (current, b) => current * 31 + b);
        }
    }
}
