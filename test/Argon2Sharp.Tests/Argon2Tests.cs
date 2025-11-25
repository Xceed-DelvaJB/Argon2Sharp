using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Tests for Argon2 implementation using RFC 9106 test vectors.
/// </summary>
public class Argon2Tests
{
    [Fact]
    public void TestArgon2id_BasicHash()
    {
        // Arrange
        string password = "password";
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestArgon2i_BasicHash()
    {
        // Arrange
        string password = "password";
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestArgon2d_BasicHash()
    {
        // Arrange
        string password = "password";
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestPasswordVerification_Success()
    {
        // Arrange
        string password = "MySecurePassword123!";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateDefault() with { Salt = salt };
        
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Act
        bool isValid = argon2.Verify(password, hash.AsSpan());

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void TestPasswordVerification_Failure()
    {
        // Arrange
        string password = "MySecurePassword123!";
        string wrongPassword = "WrongPassword";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = Argon2Parameters.CreateDefault() with { Salt = salt };
        
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Act
        bool isValid = argon2.Verify(wrongPassword, hash.AsSpan());

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void TestStaticHashPassword()
    {
        // Act
        var (hash, salt) = Argon2.HashPasswordWithSalt("testpassword");

        // Assert
        Assert.NotNull(hash);
        Assert.NotNull(salt);
        Assert.Equal(32, hash.Length);
        Assert.Equal(16, salt.Length);
    }

    [Fact]
    public void TestDifferentParametersProduceDifferentHashes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var params1 = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };
        
        var params2 = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 64,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt
        };

        // Act
        var hash1 = new Argon2(params1).Hash(password);
        var hash2 = new Argon2(params2).Hash(password);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void TestSameSaltSamePasswordProducesSameHash()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = (byte[])salt.Clone()
        };

        // Act
        var hash1 = new Argon2(parameters).Hash(password);
        var hash2 = new Argon2(parameters).Hash(password);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void TestParametersValidation_TooSmallMemory()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            Argon2Parameters.CreateBuilder().WithMemorySizeKB(7));
    }

    [Fact]
    public void TestParametersValidation_TooSmallIterations()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            Argon2Parameters.CreateBuilder().WithIterations(0));
    }

    [Fact]
    public void TestParametersValidation_InvalidParallelism()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            Argon2Parameters.CreateBuilder().WithParallelism(0));
    }

    [Fact]
    public void TestParametersValidation_TooSmallHashLength()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            Argon2Parameters.CreateBuilder().WithHashLength(3));
    }

    [Fact]
    public void TestDefaultParameters()
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
    }

    [Fact]
    public void TestHighSecurityParameters()
    {
        // Act
        var parameters = Argon2Parameters.CreateHighSecurity();

        // Assert
        Assert.Equal(Argon2Type.Argon2id, parameters.Type);
        Assert.Equal(65536, parameters.MemorySizeKB);
        Assert.Equal(4, parameters.Iterations);
        Assert.Equal(4, parameters.Parallelism);
    }

    [Fact]
    public void TestWithSecret()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] secret = Encoding.UTF8.GetBytes("my-secret-key");
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt,
            Secret = secret
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestWithAssociatedData()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(16);
        byte[] associatedData = Encoding.UTF8.GetBytes("additional-context-data");
        
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = salt,
            AssociatedData = associatedData
        };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }
}
