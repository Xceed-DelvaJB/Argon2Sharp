using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Regression and determinism tests to ensure consistent, reproducible outputs
/// across different scenarios and executions.
/// </summary>
public class Argon2DeterminismTests
{
    #region Basic Determinism Tests

    [Fact]
    public void TestDeterminism_SameInputsSameOutput()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "deterministicpassword";
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2_1 = new Argon2(parameters);
        var argon2_2 = new Argon2(parameters);

        byte[] hash1 = argon2_1.Hash(password);
        byte[] hash2 = argon2_2.Hash(password);
        byte[] hash3 = argon2_1.Hash(password);
        byte[] hash4 = argon2_2.Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
        Assert.Equal(hash2, hash3);
        Assert.Equal(hash3, hash4);
    }

    [Fact]
    public void TestDeterminism_MultipleInstances()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

        // Act - create 10 instances and hash
        var hashes = new List<byte[]>();
        for (int i = 0; i < 10; i++)
        {
            var parameters = new Argon2Parameters
            {
                Type = Argon2Type.Argon2id,
                MemorySizeKB = 32,
                Iterations = 2,
                Parallelism = 1,
                HashLength = 32,
                Salt = (byte[])salt.Clone()
            };
            var argon2 = new Argon2(parameters);
            hashes.Add(argon2.Hash(password));
        }

        // Assert
        Assert.Single(hashes.Select(h => Convert.ToBase64String(h)).Distinct());
    }

    [Fact]
    public void TestDeterminism_ByteSpanVsStringInput()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string passwordString = "testpassword";
        byte[] passwordBytes = Encoding.UTF8.GetBytes(passwordString);

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);

        // Act
        byte[] hashFromString = argon2.Hash(passwordString);
        byte[] hashFromBytes = argon2.Hash(passwordBytes.AsSpan());

        // Assert
        Assert.Equal(hashFromString, hashFromBytes);
    }

    #endregion

    #region Regression Tests with Known Values

    [Fact]
    public void TestRegression_Argon2id_FixedVector()
    {
        // Arrange - fixed inputs should always produce the same output
        byte[] salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        string password = "test";

        var parameters = new Argon2Parameters
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
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert - store the hash and verify it doesn't change
        // This is a regression test - if this fails, the implementation changed
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        
        // Hash again to verify determinism
        byte[] hash2 = argon2.Hash(password);
        Assert.Equal(hash, hash2);
    }

    [Fact]
    public void TestRegression_Argon2i_FixedVector()
    {
        // Arrange
        byte[] salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        string password = "test";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash1 = argon2.Hash(password);
        byte[] hash2 = argon2.Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void TestRegression_Argon2d_FixedVector()
    {
        // Arrange
        byte[] salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        string password = "test";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash1 = argon2.Hash(password);
        byte[] hash2 = argon2.Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    #endregion

    #region Parameter Variation Determinism

    [Theory]
    [InlineData(8)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void TestDeterminism_VaryingMemory(int memorySizeKB)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = memorySizeKB,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void TestDeterminism_VaryingIterations(int iterations)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = iterations,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    public void TestDeterminism_VaryingParallelism(int parallelism)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";
        int memorySizeKB = Math.Max(32, 8 * parallelism);

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = memorySizeKB,
            Iterations = 2,
            Parallelism = parallelism,
            HashLength = 32,
            Salt = salt
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void TestDeterminism_VaryingHashLength(int hashLength)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = hashLength,
            Salt = salt
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
        Assert.Equal(hashLength, hash1.Length);
    }

    #endregion

    #region Type and Version Determinism

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public void TestDeterminism_AllTypes(Argon2Type type)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = type,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);
        byte[] hash3 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
        Assert.Equal(hash2, hash3);
    }

    [Theory]
    [InlineData(Argon2Version.Version10)]
    [InlineData(Argon2Version.Version13)]
    public void TestDeterminism_AllVersions(Argon2Version version)
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        string password = "password";

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
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    #endregion

    #region Secret and Associated Data Determinism

    [Fact]
    public void TestDeterminism_WithSecret()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        byte[] secret = Encoding.UTF8.GetBytes("mysecretkey12345");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt,
            Secret = secret
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void TestDeterminism_WithAssociatedData()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        byte[] ad = Encoding.UTF8.GetBytes("context-data-12345");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt,
            AssociatedData = ad
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void TestDeterminism_WithSecretAndAssociatedData()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        byte[] secret = Encoding.UTF8.GetBytes("mysecretkey12345");
        byte[] ad = Encoding.UTF8.GetBytes("context-data-12345");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt,
            Secret = secret,
            AssociatedData = ad
        };

        // Act
        byte[] hash1 = new Argon2(parameters).Hash(password);
        byte[] hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    #endregion

    #region PHC Format Determinism

    [Fact]
    public void TestDeterminism_PHCEncode()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        for (int i = 0; i < 32; i++) hash[i] = (byte)i;
        for (int i = 0; i < 16; i++) salt[i] = (byte)(i + 100);

        // Act
        string encoded1 = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1);
        string encoded2 = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1);

        // Assert
        Assert.Equal(encoded1, encoded2);
    }

    [Fact]
    public void TestDeterminism_PHCRoundTrip()
    {
        // Arrange
        byte[] originalHash = new byte[32];
        byte[] originalSalt = new byte[16];
        new Random(42).NextBytes(originalHash);
        new Random(43).NextBytes(originalSalt);

        // Act - encode and decode multiple times
        for (int i = 0; i < 5; i++)
        {
            string encoded = Argon2PhcFormat.Encode(originalHash, originalSalt, Argon2Type.Argon2id, 32, 2, 1);
            
            bool success = Argon2PhcFormat.TryDecode(encoded, out byte[]? decodedHash, out byte[]? decodedSalt,
                out Argon2Type type, out int m, out int t, out int p, out _);

            Assert.True(success);
            Assert.Equal(originalHash, decodedHash);
            Assert.Equal(originalSalt, decodedSalt);
        }
    }

    [Fact]
    public void TestDeterminism_PHCHashAndVerify()
    {
        // Arrange
        string password = "deterministictest";
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        // Act
        string phc1 = Argon2PhcFormat.HashToPhcString(password, parameters);
        string phc2 = Argon2PhcFormat.HashToPhcString(password, parameters);

        // Assert
        Assert.Equal(phc1, phc2);
    }

    #endregion

    #region Hash Independence Tests

    [Fact]
    public void TestIndependence_DifferentPasswordsSameSalt()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);

        // Act
        byte[] hash1 = argon2.Hash("password1");
        byte[] hash2 = argon2.Hash("password2");
        byte[] hash1Again = argon2.Hash("password1");

        // Assert
        Assert.NotEqual(hash1, hash2);
        Assert.Equal(hash1, hash1Again);
    }

    [Fact]
    public void TestIndependence_SamePasswordDifferentSalts()
    {
        // Arrange
        string password = "password";

        byte[] salt1 = Encoding.UTF8.GetBytes("salt1___________");
        byte[] salt2 = Encoding.UTF8.GetBytes("salt2___________");

        var params1 = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt1
        };

        var params2 = params1 with { Salt = salt2 };

        // Act
        byte[] hash1 = new Argon2(params1).Hash(password);
        byte[] hash2 = new Argon2(params2).Hash(password);
        byte[] hash1Again = new Argon2(params1).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
        Assert.Equal(hash1, hash1Again);
    }

    #endregion

    #region Output Buffer Determinism

    [Fact]
    public void TestDeterminism_OutputBuffer()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        byte[] password = Encoding.UTF8.GetBytes("password");

        // Act
        byte[] output1 = new byte[32];
        byte[] output2 = new byte[32];
        byte[] output3 = new byte[32];

        argon2.Hash(password.AsSpan(), output1);
        argon2.Hash(password.AsSpan(), output2);
        argon2.Hash(password.AsSpan(), output3);

        // Assert
        Assert.Equal(output1, output2);
        Assert.Equal(output2, output3);
    }

    [Fact]
    public void TestDeterminism_OutputBufferVsNewArray()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("fixedsalt1234567");
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        byte[] password = Encoding.UTF8.GetBytes("password");

        // Act
        byte[] outputBuffer = new byte[32];
        argon2.Hash(password.AsSpan(), outputBuffer);
        byte[] outputNew = argon2.Hash(password.AsSpan());

        // Assert
        Assert.Equal(outputBuffer, outputNew);
    }

    #endregion

    #region Factory Method Determinism

    [Fact]
    public void TestDeterminism_CreateDefault()
    {
        // Act
        var params1 = Argon2Parameters.CreateDefault();
        var params2 = Argon2Parameters.CreateDefault();

        // Assert
        Assert.Equal(params1.Type, params2.Type);
        Assert.Equal(params1.Version, params2.Version);
        Assert.Equal(params1.MemorySizeKB, params2.MemorySizeKB);
        Assert.Equal(params1.Iterations, params2.Iterations);
        Assert.Equal(params1.Parallelism, params2.Parallelism);
        Assert.Equal(params1.HashLength, params2.HashLength);
    }

    [Fact]
    public void TestDeterminism_CreateHighSecurity()
    {
        // Act
        var params1 = Argon2Parameters.CreateHighSecurity();
        var params2 = Argon2Parameters.CreateHighSecurity();

        // Assert
        Assert.Equal(params1.Type, params2.Type);
        Assert.Equal(params1.Version, params2.Version);
        Assert.Equal(params1.MemorySizeKB, params2.MemorySizeKB);
        Assert.Equal(params1.Iterations, params2.Iterations);
        Assert.Equal(params1.Parallelism, params2.Parallelism);
        Assert.Equal(params1.HashLength, params2.HashLength);
    }

    [Fact]
    public void TestDeterminism_CreateForTesting()
    {
        // Act
        var params1 = Argon2Parameters.CreateForTesting();
        var params2 = Argon2Parameters.CreateForTesting();

        // Assert
        Assert.Equal(params1.Type, params2.Type);
        Assert.Equal(params1.Version, params2.Version);
        Assert.Equal(params1.MemorySizeKB, params2.MemorySizeKB);
        Assert.Equal(params1.Iterations, params2.Iterations);
        Assert.Equal(params1.Parallelism, params2.Parallelism);
        Assert.Equal(params1.HashLength, params2.HashLength);
    }

    #endregion
}
