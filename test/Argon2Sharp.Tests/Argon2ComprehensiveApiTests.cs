using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Additional comprehensive tests to ensure complete API coverage
/// and specific scenarios for Blake2b, Builder pattern, and edge cases.
/// </summary>
public class Argon2ComprehensiveApiTests
{
    #region Builder Pattern Complete Coverage

    [Fact]
    public void TestBuilder_FullConfiguration()
    {
        // Arrange & Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithType(Argon2Type.Argon2id)
            .WithVersion(Argon2Version.Version13)
            .WithMemorySizeKB(64)
            .WithIterations(3)
            .WithParallelism(2)
            .WithHashLength(48)
            .WithRandomSalt(24)
            .WithSecret(Encoding.UTF8.GetBytes("secret"))
            .WithAssociatedData(Encoding.UTF8.GetBytes("context"))
            .WithMaxDegreeOfParallelism(4)
            .Build();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(Argon2Version.Version13, parameters.Version);
        Assert.Equal(64, parameters.MemorySizeKB);
        Assert.Equal(3, parameters.Iterations);
        Assert.Equal(2, parameters.Parallelism);
        Assert.Equal(48, parameters.HashLength);
        Assert.NotNull(parameters.Salt);
        Assert.Equal(24, parameters.Salt!.Length);
        Assert.NotNull(parameters.Secret);
        Assert.NotNull(parameters.AssociatedData);
        Assert.Equal(4, parameters.MaxDegreeOfParallelism);
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public void TestBuilder_WithType_AllTypes(Argon2Type type)
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithType(type)
            .WithRandomSalt()
            .Build();

        // Assert
        Assert.Equal(type, parameters.Type);
    }

    [Theory]
    [InlineData(Argon2Version.Version10)]
    [InlineData(Argon2Version.Version13)]
    public void TestBuilder_WithVersion_AllVersions(Argon2Version version)
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithVersion(version)
            .WithRandomSalt()
            .Build();

        // Assert
        Assert.Equal(version, parameters.Version);
    }

    [Fact]
    public void TestBuilder_WithNullSecret_SetsNull()
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithSecret(new byte[] { 1, 2, 3 })
            .WithSecret(null)
            .WithRandomSalt()
            .Build();

        // Assert
        Assert.Null(parameters.Secret);
    }

    [Fact]
    public void TestBuilder_WithNullAssociatedData_SetsNull()
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithAssociatedData(new byte[] { 1, 2, 3 })
            .WithAssociatedData(null)
            .WithRandomSalt()
            .Build();

        // Assert
        Assert.Null(parameters.AssociatedData);
    }

    [Fact]
    public void TestBuilder_WithNullMaxDegreeOfParallelism()
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMaxDegreeOfParallelism(4)
            .WithMaxDegreeOfParallelism(null)
            .WithRandomSalt()
            .Build();

        // Assert
        Assert.Null(parameters.MaxDegreeOfParallelism);
    }

    [Fact]
    public void TestBuilder_SecretIsCopied()
    {
        // Arrange
        byte[] secret = new byte[] { 1, 2, 3 };

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithSecret(secret)
            .WithRandomSalt()
            .Build();

        secret[0] = 99; // Modify original

        // Assert - should not affect parameters
        Assert.NotNull(parameters.Secret);
        Assert.Equal(1, parameters.Secret![0]);
    }

    [Fact]
    public void TestBuilder_AssociatedDataIsCopied()
    {
        // Arrange
        byte[] ad = new byte[] { 1, 2, 3 };

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithAssociatedData(ad)
            .WithRandomSalt()
            .Build();

        ad[0] = 99; // Modify original

        // Assert - should not affect parameters
        Assert.NotNull(parameters.AssociatedData);
        Assert.Equal(1, parameters.AssociatedData![0]);
    }

    [Fact]
    public void TestBuilder_SaltIsCopied()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        byte originalFirst = salt[0];

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithSalt(salt)
            .Build();

        salt[0] = (byte)(originalFirst ^ 0xFF); // Modify original

        // Assert - should not affect parameters
        Assert.Equal(originalFirst, parameters.Salt![0]);
    }

    #endregion

    #region Record Equality and Immutability Tests

    [Fact]
    public void TestParameters_EqualityWithSameSalt()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var params1 = Argon2Parameters.CreateDefault() with { Salt = salt };
        var params2 = Argon2Parameters.CreateDefault() with { Salt = salt };

        // Assert - reference comparison for arrays
        Assert.Equal(params1.MemorySizeKB, params2.MemorySizeKB);
        Assert.Equal(params1.Iterations, params2.Iterations);
        Assert.Equal(params1.Parallelism, params2.Parallelism);
    }

    [Fact]
    public void TestParameters_WithExpression_AllProperties()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var original = Argon2Parameters.CreateDefault() with { Salt = salt };

        // Act
        var modified = original with
        {
            Type = Argon2Type.Argon2i,
            Version = Argon2Version.Version10,
            MemorySizeKB = 128,
            Iterations = 5,
            Parallelism = 2,
            HashLength = 64
        };

        // Assert - original unchanged
        Assert.Equal(Argon2Type.Argon2id, original.Type);
        Assert.Equal(Argon2Version.Version13, original.Version);
        Assert.Equal(19456, original.MemorySizeKB);
        Assert.Equal(2, original.Iterations);
        Assert.Equal(1, original.Parallelism);
        Assert.Equal(32, original.HashLength);

        // Assert - modified has new values
        Assert.Equal(Argon2Type.Argon2i, modified.Type);
        Assert.Equal(Argon2Version.Version10, modified.Version);
        Assert.Equal(128, modified.MemorySizeKB);
        Assert.Equal(5, modified.Iterations);
        Assert.Equal(2, modified.Parallelism);
        Assert.Equal(64, modified.HashLength);
    }

    #endregion

    #region Span API Tests

    [Fact]
    public void TestHash_SpanInput_EmptyPassword()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act
        byte[] hash = argon2.Hash(ReadOnlySpan<byte>.Empty);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestHash_SpanOutput_CorrectLength()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt, HashLength = 64 };
        var argon2 = new Argon2(parameters);
        byte[] output = new byte[64];

        // Act
        argon2.Hash(Encoding.UTF8.GetBytes("password").AsSpan(), output);

        // Assert
        Assert.True(output.Any(b => b != 0));
    }

    [Fact]
    public void TestVerify_SpanInput_CorrectPassword()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] password = Encoding.UTF8.GetBytes("testpassword");
        byte[] hash = argon2.Hash(password.AsSpan());

        // Act
        bool result = argon2.Verify(password.AsSpan(), hash.AsSpan());

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void TestVerify_SpanInput_WrongPassword()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(Encoding.UTF8.GetBytes("correct").AsSpan());

        // Act
        bool result = argon2.Verify(Encoding.UTF8.GetBytes("wrong").AsSpan(), hash.AsSpan());

        // Assert
        Assert.False(result);
    }

    #endregion

    #region PHC Format Advanced Tests

    [Fact]
    public void TestPhcFormat_HashToPhcString_WithParameters()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(64)
            .WithIterations(4)
            .WithParallelism(2)
            .WithHashLength(48)
            .WithRandomSalt(20)
            .Build();

        // Act
        string phcHash = Argon2PhcFormat.HashToPhcString("password", parameters);

        // Assert
        Assert.Contains("m=64", phcHash);
        Assert.Contains("t=4", phcHash);
        Assert.Contains("p=2", phcHash);
    }

    [Fact]
    public void TestPhcFormat_HashToPhcStringWithAutoSalt_DefaultParams()
    {
        // Act
        string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("password");

        // Assert
        Assert.StartsWith("$argon2id$", phcHash);
        Assert.Contains("v=19", phcHash);
    }

    [Fact]
    public void TestPhcFormat_HashToPhcStringWithAutoSalt_CustomParams()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(64)
            .WithIterations(3)
            .WithParallelism(2)
            .BuildWithoutSaltValidation();

        // Act
        string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("password", parameters, 20);

        // Assert
        Assert.Contains("m=64", phcHash);
        Assert.Contains("t=3", phcHash);
        Assert.Contains("p=2", phcHash);
    }

    [Fact]
    public void TestPhcFormat_VerifyPhcString_ReturnsParameters()
    {
        // Arrange
        string phcHash = Argon2PhcFormat.HashPassword("password", memorySizeKB: 32, iterations: 3, parallelism: 2);

        // Act
        var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("password", phcHash);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(parameters);
        Assert.Equal(32, parameters!.MemorySizeKB);
        Assert.Equal(3, parameters.Iterations);
        Assert.Equal(2, parameters.Parallelism);
    }

    [Fact]
    public void TestPhcFormat_VerifyPhcString_WrongPassword_NoParameters()
    {
        // Arrange
        string phcHash = Argon2PhcFormat.HashPassword("correct", memorySizeKB: 32, iterations: 2, parallelism: 1);

        // Act
        var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("wrong", phcHash);

        // Assert
        Assert.False(isValid);
        Assert.Null(parameters);
    }

    [Fact]
    public void TestPhcFormat_TryDecode_WithParameters()
    {
        // Arrange
        string phcHash = Argon2PhcFormat.HashPassword("password", memorySizeKB: 32, iterations: 2, parallelism: 1);

        // Act
        bool success = Argon2PhcFormat.TryDecode(phcHash, out byte[]? hash, out Argon2Parameters? parameters);

        // Assert
        Assert.True(success);
        Assert.NotNull(hash);
        Assert.NotNull(parameters);
        Assert.Equal(32, parameters!.MemorySizeKB);
    }

    #endregion

    #region Salt Generation Tests

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void TestGenerateSalt_VariousLengths_CorrectSize(int length)
    {
        // Act
        byte[] salt = Argon2.GenerateSalt(length);

        // Assert
        Assert.Equal(length, salt.Length);
    }

    [Fact]
    public void TestGenerateSalt_DefaultLength()
    {
        // Act
        byte[] salt = Argon2.GenerateSalt();

        // Assert
        Assert.Equal(16, salt.Length);
    }

    [Fact]
    public void TestGenerateSalt_Randomness()
    {
        // Act
        var salts = Enumerable.Range(0, 50).Select(_ => Argon2.GenerateSalt(32)).ToList();

        // Assert - all should be unique
        var uniqueCount = salts.Select(s => Convert.ToBase64String(s)).Distinct().Count();
        Assert.Equal(50, uniqueCount);
    }

    #endregion

    #region Factory Method Parameter Values Tests

    [Fact]
    public void TestCreateDefault_CorrectValues()
    {
        // Act
        var parameters = Argon2Parameters.CreateDefault();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(Argon2Version.Version13, parameters.Version);
        Assert.Equal(19456, parameters.MemorySizeKB);
        Assert.Equal(2, parameters.Iterations);
        Assert.Equal(1, parameters.Parallelism);
        Assert.Equal(32, parameters.HashLength);
        Assert.Null(parameters.Salt);
        Assert.Null(parameters.Secret);
        Assert.Null(parameters.AssociatedData);
    }

    [Fact]
    public void TestCreateHighSecurity_CorrectValues()
    {
        // Act
        var parameters = Argon2Parameters.CreateHighSecurity();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(Argon2Version.Version13, parameters.Version);
        Assert.Equal(65536, parameters.MemorySizeKB);
        Assert.Equal(4, parameters.Iterations);
        Assert.Equal(4, parameters.Parallelism);
        Assert.Equal(32, parameters.HashLength);
    }

    [Fact]
    public void TestCreateForTesting_CorrectValues()
    {
        // Act
        var parameters = Argon2Parameters.CreateForTesting();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(Argon2Version.Version13, parameters.Version);
        Assert.Equal(32, parameters.MemorySizeKB);
        Assert.Equal(3, parameters.Iterations);
        Assert.Equal(4, parameters.Parallelism);
        Assert.Equal(32, parameters.HashLength);
    }

    #endregion

    #region Hash Consistency with Different Input Types

    [Fact]
    public void TestHash_StringVsBytesVsSpan_SameResult()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        string passwordStr = "testpassword";
        byte[] passwordBytes = Encoding.UTF8.GetBytes(passwordStr);

        // Act
        byte[] hashFromString = argon2.Hash(passwordStr);
        byte[] hashFromSpan = argon2.Hash(passwordBytes.AsSpan());

        // Assert
        Assert.Equal(hashFromString, hashFromSpan);
    }

    #endregion

    #region Memory Parameter Relationship Tests

    [Theory]
    [InlineData(8, 1)]
    [InlineData(16, 2)]
    [InlineData(32, 4)]
    [InlineData(64, 8)]
    public void TestMemory_MinimumForParallelism(int memorySizeKB, int parallelism)
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(memorySizeKB)
            .WithIterations(1)
            .WithParallelism(parallelism)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.NotNull(hash);
    }

    #endregion

    #region Type Enum Coverage Tests

    [Fact]
    public void TestArgon2Type_AllValuesValid()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var types = Enum.GetValues<Argon2Type>();

        // Act & Assert
        foreach (var type in types)
        {
            var parameters = new Argon2Parameters
            {
                Type = type,
                MemorySizeKB = 32,
                Iterations = 2,
                Parallelism = 1,
                HashLength = 32,
                Salt = salt
            };

            var argon2 = new Argon2(parameters);
            byte[] hash = argon2.Hash("password");
            Assert.NotNull(hash);
        }
    }

    [Fact]
    public void TestArgon2Version_AllValuesValid()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var versions = Enum.GetValues<Argon2Version>();

        // Act & Assert
        foreach (var version in versions)
        {
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

            var argon2 = new Argon2(parameters);
            byte[] hash = argon2.Hash("password");
            Assert.NotNull(hash);
        }
    }

    #endregion

    #region Verify Method Return Value Tests

    [Fact]
    public void TestVerify_AllZerosHash_ReturnsFalse()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] allZerosHash = new byte[32]; // All zeros

        // Act
        bool result = argon2.Verify("password", allZerosHash.AsSpan());

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void TestVerify_AllOnesHash_ReturnsFalse()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] allOnesHash = new byte[32];
        Array.Fill(allOnesHash, (byte)0xFF);

        // Act
        bool result = argon2.Verify("password", allOnesHash.AsSpan());

        // Assert
        Assert.False(result);
    }

    #endregion

    #region Hash Uniqueness Per Parameter Combination

    [Fact]
    public void TestHash_UniquePerType()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";
        var hashes = new Dictionary<Argon2Type, byte[]>();

        // Act
        foreach (var type in Enum.GetValues<Argon2Type>())
        {
            var parameters = new Argon2Parameters
            {
                Type = type,
                MemorySizeKB = 32,
                Iterations = 2,
                Parallelism = 1,
                HashLength = 32,
                Salt = salt
            };
            hashes[type] = new Argon2(parameters).Hash(password);
        }

        // Assert - all types produce different hashes
        var uniqueHashes = hashes.Values.Select(h => Convert.ToBase64String(h)).Distinct().Count();
        Assert.Equal(3, uniqueHashes);
    }

    [Fact]
    public void TestHash_UniquePerVersion()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";
        var hashes = new Dictionary<Argon2Version, byte[]>();

        // Act
        foreach (var version in Enum.GetValues<Argon2Version>())
        {
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
            hashes[version] = new Argon2(parameters).Hash(password);
        }

        // Assert - different versions produce different hashes
        var uniqueHashes = hashes.Values.Select(h => Convert.ToBase64String(h)).Distinct().Count();
        Assert.Equal(2, uniqueHashes);
    }

    #endregion
}
