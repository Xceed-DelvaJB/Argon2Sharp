using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Edge case and boundary condition tests for Argon2 implementation.
/// Tests extreme parameter values and unusual input scenarios.
/// </summary>
public class Argon2EdgeCaseTests
{
    #region Empty and Null Password Tests

    [Fact]
    public void TestEmptyPassword_ShouldProduceValidHash()
    {
        // Arrange
        string password = "";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
        Assert.True(hash.Any(b => b != 0)); // Hash should not be all zeros
    }

    [Fact]
    public void TestEmptyPassword_Verification()
    {
        // Arrange
        string password = "";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Act & Assert
        Assert.True(argon2.Verify(password, hash.AsSpan()));
        Assert.False(argon2.Verify("not-empty", hash.AsSpan()));
    }

    [Fact]
    public void TestEmptyByteArrayPassword()
    {
        // Arrange
        byte[] password = Array.Empty<byte>();
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password.AsSpan());

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    #endregion

    #region Minimum Salt Tests

    [Fact]
    public void TestMinimumSaltLength_8Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = new byte[8]; // Minimum allowed salt length
        new Random(42).NextBytes(salt);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestSaltTooShort_ShouldThrowOnValidation()
    {
        // Arrange
        byte[] salt = new byte[7]; // Below minimum

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            Argon2Parameters.CreateBuilder()
                .WithSalt(salt)
                .Build());
    }

    [Fact]
    public void TestLongSalt_256Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = new byte[256];
        new Random(42).NextBytes(salt);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    #endregion

    #region Minimum Parameter Tests

    [Fact]
    public void TestMinimumMemory_8KB()
    {
        // Arrange
        string password = "password";
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
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestMinimumIterations_1()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(1)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestMinimumParallelism_1()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(3)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestMinimumHashLength_4Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(3)
            .WithParallelism(4)
            .WithHashLength(4) // Minimum
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.Equal(4, hash.Length);
    }

    #endregion

    #region Large Hash Output Tests

    [Fact]
    public void TestLargeHashOutput_64Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with 
        { 
            Salt = salt,
            HashLength = 64 
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void TestLargeHashOutput_128Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with 
        { 
            Salt = salt,
            HashLength = 128 
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.Equal(128, hash.Length);
    }

    [Fact]
    public void TestLargeHashOutput_256Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with 
        { 
            Salt = salt,
            HashLength = 256 
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.Equal(256, hash.Length);
    }

    #endregion

    #region Unicode Password Tests

    [Fact]
    public void TestUnicodePassword_Chinese()
    {
        // Arrange
        string password = "密码测试";
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
    public void TestUnicodePassword_Emoji()
    {
        // Arrange
        string password = "🔐🔑🔒";
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
    public void TestUnicodePassword_Mixed()
    {
        // Arrange
        string password = "Пароль123パスワードكلمة";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.True(argon2.Verify(password, hash.AsSpan()));
    }

    #endregion

    #region Builder Pattern Tests

    [Fact]
    public void TestBuilder_FluentAPI()
    {
        // Arrange & Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithType(Argon2Type.Argon2id)
            .WithVersion(Argon2Version.Version13)
            .WithMemorySizeKB(65536)
            .WithIterations(4)
            .WithParallelism(4)
            .WithHashLength(64)
            .WithRandomSalt(32)
            .Build();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(Argon2Version.Version13, parameters.Version);
        Assert.Equal(65536, parameters.MemorySizeKB);
        Assert.Equal(4, parameters.Iterations);
        Assert.Equal(4, parameters.Parallelism);
        Assert.Equal(64, parameters.HashLength);
        Assert.NotNull(parameters.Salt);
        Assert.Equal(32, parameters.Salt!.Length);
    }

    [Fact]
    public void TestBuilder_WithSecret()
    {
        // Arrange
        byte[] secret = Encoding.UTF8.GetBytes("my-secret-key");
        byte[] salt = Argon2.GenerateSalt(16);

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(3)
            .WithParallelism(4)
            .WithSalt(salt)
            .WithSecret(secret)
            .Build();

        // Assert
        Assert.NotNull(parameters.Secret);
        Assert.Equal(secret.Length, parameters.Secret!.Length);
    }

    [Fact]
    public void TestBuilder_WithAssociatedData()
    {
        // Arrange
        byte[] ad = Encoding.UTF8.GetBytes("additional-data");
        byte[] salt = Argon2.GenerateSalt(16);

        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(3)
            .WithParallelism(4)
            .WithSalt(salt)
            .WithAssociatedData(ad)
            .Build();

        // Assert
        Assert.NotNull(parameters.AssociatedData);
        Assert.Equal(ad.Length, parameters.AssociatedData!.Length);
    }

    [Fact]
    public void TestBuilder_BuildWithoutSaltValidation()
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(3)
            .WithParallelism(4)
            .BuildWithoutSaltValidation();

        // Assert
        Assert.Null(parameters.Salt);
        Assert.Equal(32, parameters.MemorySizeKB);
    }

    #endregion

    #region Parallel Processing Tests

    [Fact]
    public void TestParallelProcessing_Enabled()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 64,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt,
            MaxDegreeOfParallelism = 4
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestMaxDegreeOfParallelism_ParameterIsAccepted()
    {
        // Arrange - MaxDegreeOfParallelism is currently reserved for future use
        // The parameter is accepted but sequential processing is used for correctness
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 64,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt,
            MaxDegreeOfParallelism = 4 // Parameter accepted, sequential used internally
        };

        // Act - should not throw
        byte[] hash = new Argon2(parameters).Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    #endregion

    #region Record Immutability Tests

    [Fact]
    public void TestParameters_WithExpression()
    {
        // Arrange
        var original = Argon2Parameters.CreateDefault();

        // Act
        var modified = original with { MemorySizeKB = 65536 };

        // Assert
        Assert.Equal(19456, original.MemorySizeKB);
        Assert.Equal(65536, modified.MemorySizeKB);
        Assert.NotSame(original, modified);
    }

    [Fact]
    public void TestParameters_Equality()
    {
        // Arrange
        var params1 = Argon2Parameters.CreateDefault();
        var params2 = Argon2Parameters.CreateDefault();

        // Assert
        Assert.Equal(params1, params2);
    }

    #endregion
}
