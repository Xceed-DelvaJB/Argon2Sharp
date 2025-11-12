using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Tests for PHC string format encoding/decoding.
/// </summary>
public class Argon2PhcFormatTests
{
    [Fact]
    public void TestEncode()
    {
        // Arrange
        byte[] hash = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] salt = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        
        // Act
        string encoded = Argon2PhcFormat.Encode(
            hash, salt, Argon2Type.Argon2id, 19456, 2, 1);

        // Assert
        Assert.StartsWith("$argon2id$v=19$m=19456,t=2,p=1$", encoded);
    }

    [Fact]
    public void TestDecode()
    {
        // Arrange
        string phc = "$argon2id$v=19$m=19456,t=2,p=1$BQYHCAkKCwwNDg8Q$AQIDBAUGBwgJCgsMDQ4PEA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(
            phc,
            out byte[]? hash,
            out byte[]? salt,
            out Argon2Type type,
            out int memorySizeKB,
            out int iterations,
            out int parallelism,
            out Argon2Version version);

        // Assert
        Assert.True(success);
        Assert.NotNull(hash);
        Assert.NotNull(salt);
        Assert.Equal(Argon2Type.Argon2id, type);
        Assert.Equal(19456, memorySizeKB);
        Assert.Equal(2, iterations);
        Assert.Equal(1, parallelism);
        Assert.Equal(Argon2Version.Version13, version);
    }

    [Fact]
    public void TestHashAndVerifyWithPhcFormat()
    {
        // Arrange
        string password = "MySecurePassword123!";

        // Act
        string phcHash = Argon2PhcFormat.HashPassword(password, 
            memorySizeKB: 32, iterations: 3, parallelism: 4);
        bool isValid = Argon2PhcFormat.VerifyPassword(password, phcHash);
        bool isInvalid = Argon2PhcFormat.VerifyPassword("WrongPassword", phcHash);

        // Assert
        Assert.True(isValid);
        Assert.False(isInvalid);
    }

    [Fact]
    public void TestEncodeDecode_RoundTrip()
    {
        // Arrange
        byte[] originalHash = new byte[32];
        byte[] originalSalt = new byte[16];
        Random.Shared.NextBytes(originalHash);
        Random.Shared.NextBytes(originalSalt);

        // Act
        string encoded = Argon2PhcFormat.Encode(
            originalHash, originalSalt, Argon2Type.Argon2id, 65536, 4, 4);
        
        bool success = Argon2PhcFormat.TryDecode(
            encoded,
            out byte[]? decodedHash,
            out byte[]? decodedSalt,
            out Argon2Type type,
            out int memorySizeKB,
            out int iterations,
            out int parallelism,
            out Argon2Version version);

        // Assert
        Assert.True(success);
        Assert.Equal(originalHash, decodedHash);
        Assert.Equal(originalSalt, decodedSalt);
        Assert.Equal(Argon2Type.Argon2id, type);
        Assert.Equal(65536, memorySizeKB);
        Assert.Equal(4, iterations);
        Assert.Equal(4, parallelism);
    }

    [Fact]
    public void TestDecode_InvalidFormat()
    {
        // Arrange
        string invalidPhc = "invalid-format";

        // Act
        bool success = Argon2PhcFormat.TryDecode(
            invalidPhc,
            out byte[]? hash,
            out byte[]? salt,
            out Argon2Type type,
            out int memorySizeKB,
            out int iterations,
            out int parallelism,
            out Argon2Version version);

        // Assert
        Assert.False(success);
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public void TestAllArgon2Types(Argon2Type argonType)
    {
        // Arrange
        string password = "password";
        
        // Act
        string phcHash = Argon2PhcFormat.HashPassword(
            password, 
            type: argonType,
            memorySizeKB: 32,
            iterations: 3,
            parallelism: 4);
        
        bool isValid = Argon2PhcFormat.VerifyPassword(password, phcHash);

        // Assert
        Assert.True(isValid);
        Assert.Contains($"argon2{argonType.ToString().ToLower().Replace("argon2", "")}", phcHash);
    }
}
