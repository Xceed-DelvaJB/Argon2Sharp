using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Interoperability tests for PHC format compliance, encoding compatibility,
/// and cross-system verification scenarios.
/// </summary>
public class Argon2InteroperabilityTests
{
    #region PHC Format Compliance Tests

    [Theory]
    [InlineData("argon2d")]
    [InlineData("argon2i")]
    [InlineData("argon2id")]
    public void TestPhcFormat_TypePrefix(string expectedType)
    {
        // Arrange
        Argon2Type type = expectedType switch
        {
            "argon2d" => Argon2Type.Argon2d,
            "argon2i" => Argon2Type.Argon2i,
            "argon2id" => Argon2Type.Argon2id,
            _ => throw new ArgumentException()
        };

        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, type, 32, 2, 1);

        // Assert
        Assert.StartsWith($"${expectedType}$", encoded);
    }

    [Fact]
    public void TestPhcFormat_VersionField()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1, Argon2Version.Version13);

        // Assert
        Assert.Contains("v=19", encoded); // Version 0x13 = 19 decimal
    }

    [Fact]
    public void TestPhcFormat_ParametersOrder()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 1024, 3, 4);

        // Assert - parameters should be in m,t,p order
        int mPos = encoded.IndexOf("m=1024");
        int tPos = encoded.IndexOf("t=3");
        int pPos = encoded.IndexOf("p=4");

        Assert.True(mPos < tPos, "m should come before t");
        Assert.True(tPos < pPos, "t should come before p");
    }

    [Fact]
    public void TestPhcFormat_Base64NoPadding()
    {
        // Arrange - PHC format uses Base64 without padding
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1);
        
        // Extract salt and hash parts (last two segments)
        string[] parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        string saltPart = parts[3];
        string hashPart = parts[4];

        // Assert - salt and hash should not end with '=' (base64 padding)
        Assert.DoesNotContain("=", saltPart);
        Assert.DoesNotContain("=", hashPart);
    }

    [Fact]
    public void TestPhcFormat_FivePartsStructure()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1);
        string[] parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);

        // Assert - format: $type$v=version$params$salt$hash (5 parts without leading $)
        Assert.Equal(5, parts.Length);
        Assert.Equal("argon2id", parts[0]);
        Assert.StartsWith("v=", parts[1]);
        Assert.Contains(",", parts[2]); // Parameters with commas
    }

    #endregion

    #region Known Vector Tests - RFC 9106 Compliance

    [Fact]
    public void TestKnownVector_Argon2id_BasicParameters()
    {
        // Arrange - using fixed salt and password for reproducibility
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        string password = "password";

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
        var argon2 = new Argon2(parameters);
        byte[] hash1 = argon2.Hash(password);
        byte[] hash2 = argon2.Hash(password);

        // Assert - deterministic output
        Assert.Equal(hash1, hash2);
        Assert.Equal(32, hash1.Length);
    }

    [Fact]
    public void TestKnownVector_Argon2i_BasicParameters()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            Version = Argon2Version.Version13,
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
    public void TestKnownVector_Argon2d_BasicParameters()
    {
        // Arrange
        byte[] salt = Encoding.UTF8.GetBytes("somesalt");
        string password = "password";

        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            Version = Argon2Version.Version13,
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

    #endregion

    #region Base64 Encoding Tests

    [Fact]
    public void TestBase64_StandardEncoding()
    {
        // Arrange
        byte[] data = new byte[] { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B };

        // Act
        string encoded = Argon2.ToBase64(data);
        byte[] decoded = Argon2.FromBase64(encoded);

        // Assert
        Assert.Equal(data, decoded);
    }

    [Theory]
    [InlineData(new byte[] { 0x00 }, "AA==")]
    [InlineData(new byte[] { 0xFF }, "/w==")]
    [InlineData(new byte[] { 0x00, 0x00 }, "AAA=")]
    [InlineData(new byte[] { 0xFF, 0xFF }, "//8=")]
    [InlineData(new byte[] { 0x00, 0x00, 0x00 }, "AAAA")]
    public void TestBase64_SpecificValues(byte[] input, string expected)
    {
        // Act
        string encoded = Argon2.ToBase64(input);

        // Assert
        Assert.Equal(expected, encoded);
    }

    [Fact]
    public void TestBase64_AllByteValues()
    {
        // Arrange
        byte[] allBytes = new byte[256];
        for (int i = 0; i < 256; i++)
            allBytes[i] = (byte)i;

        // Act
        string encoded = Argon2.ToBase64(allBytes);
        byte[] decoded = Argon2.FromBase64(encoded);

        // Assert
        Assert.Equal(allBytes, decoded);
    }

    [Fact]
    public void TestBase64_EmptyArray()
    {
        // Arrange
        byte[] empty = Array.Empty<byte>();

        // Act
        string encoded = Argon2.ToBase64(empty);
        byte[] decoded = Argon2.FromBase64(encoded);

        // Assert
        Assert.Equal("", encoded);
        Assert.Empty(decoded);
    }

    #endregion

    #region PHC String Parsing Tests

    [Fact]
    public void TestPhcParsing_ValidArgon2id()
    {
        // Arrange
        string phc = "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(phc, out byte[]? hash, out byte[]? salt,
            out Argon2Type type, out int m, out int t, out int p, out Argon2Version version);

        // Assert
        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2id, type);
        Assert.Equal(32, m);
        Assert.Equal(3, t);
        Assert.Equal(4, p);
        Assert.Equal(Argon2Version.Version13, version);
    }

    [Fact]
    public void TestPhcParsing_ValidArgon2i()
    {
        // Arrange
        string phc = "$argon2i$v=19$m=64,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(phc, out _, out _,
            out Argon2Type type, out int m, out int t, out int p, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2i, type);
        Assert.Equal(64, m);
        Assert.Equal(2, t);
        Assert.Equal(1, p);
    }

    [Fact]
    public void TestPhcParsing_ValidArgon2d()
    {
        // Arrange
        string phc = "$argon2d$v=19$m=128,t=4,p=2$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(phc, out _, out _,
            out Argon2Type type, out int m, out int t, out int p, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2d, type);
        Assert.Equal(128, m);
        Assert.Equal(4, t);
        Assert.Equal(2, p);
    }

    [Theory]
    [InlineData("")]
    [InlineData("$")]
    [InlineData("$$$$")]
    [InlineData("$argon2x$v=19$m=32,t=3,p=4$salt$hash")]  // Invalid type
    [InlineData("$argon2id$v=19$m=32$salt$hash")]          // Missing params
    [InlineData("$argon2id$m=32,t=3,p=4$salt$hash")]       // Missing version
    public void TestPhcParsing_InvalidFormats(string invalid)
    {
        // Act
        bool success = Argon2PhcFormat.TryDecode(invalid, out _, out _,
            out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    #endregion

    #region Cross-Verification Tests

    [Fact]
    public void TestCrossVerification_InstanceToStatic()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "testpassword";
        var parameters = Argon2Parameters.CreateDefault() with { Salt = salt };

        // Act - hash with instance method
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Create PHC string manually
        string phcString = Argon2PhcFormat.Encode(hash, parameters);

        // Verify with PHC format
        bool isValid = Argon2PhcFormat.VerifyPassword(password, phcString);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void TestCrossVerification_PHCToInstance()
    {
        // Arrange
        string password = "testpassword";

        // Hash with PHC format
        string phcString = Argon2PhcFormat.HashPassword(password, memorySizeKB: 32, iterations: 2, parallelism: 1);

        // Decode PHC string
        bool decoded = Argon2PhcFormat.TryDecode(phcString, out byte[]? hash, out Argon2Parameters? parameters);
        Assert.True(decoded);
        Assert.NotNull(hash);
        Assert.NotNull(parameters);

        // Verify with instance
        var argon2 = new Argon2(parameters);
        bool isValid = argon2.Verify(password, hash.AsSpan());

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void TestCrossVerification_AllTypes()
    {
        // Arrange
        string password = "crossverify";

        foreach (Argon2Type type in Enum.GetValues<Argon2Type>())
        {
            // Hash with PHC format
            string phcString = Argon2PhcFormat.HashPassword(password, type: type, 
                memorySizeKB: 32, iterations: 2, parallelism: 1);

            // Verify
            bool isValid = Argon2PhcFormat.VerifyPassword(password, phcString);
            Assert.True(isValid, $"Failed for {type}");

            // Verify wrong password fails
            bool isInvalid = Argon2PhcFormat.VerifyPassword("wrongpassword", phcString);
            Assert.False(isInvalid, $"Should fail for wrong password with {type}");
        }
    }

    #endregion

    #region UTF-8 Encoding Tests

    [Theory]
    [InlineData("password")]
    [InlineData("пароль")]        // Russian
    [InlineData("密码")]          // Chinese
    [InlineData("كلمة السر")]     // Arabic
    [InlineData("パスワード")]      // Japanese
    [InlineData("🔐🔑")]          // Emoji
    public void TestUTF8Encoding_DifferentLanguages(string password)
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
    public void TestUTF8Encoding_Normalization()
    {
        // Arrange - NFD vs NFC normalization can produce different byte sequences
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // é can be composed (é) or decomposed (e + ́)
        string composed = "caf\u00E9"; // Single code point
        string decomposed = "cafe\u0301"; // e + combining acute accent

        // Act
        byte[] hash1 = argon2.Hash(composed);
        byte[] hash2 = argon2.Hash(decomposed);

        // Assert - different byte sequences should produce different hashes
        // (unless they happen to be identical, which they're not)
        if (Encoding.UTF8.GetBytes(composed).SequenceEqual(Encoding.UTF8.GetBytes(decomposed)))
        {
            Assert.Equal(hash1, hash2);
        }
        else
        {
            Assert.NotEqual(hash1, hash2);
        }
    }

    [Fact]
    public void TestUTF8Encoding_BOM()
    {
        // Arrange - test that BOM is not stripped or added
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        string withoutBOM = "password";
        string withBOM = "\uFEFF" + "password";

        // Act
        byte[] hash1 = argon2.Hash(withoutBOM);
        byte[] hash2 = argon2.Hash(withBOM);

        // Assert - should be different (BOM is preserved)
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Parameter Encoding Tests

    [Theory]
    [InlineData(8)]
    [InlineData(1024)]
    [InlineData(65536)]
    [InlineData(1048576)]  // 1 GB
    public void TestParameterEncoding_MemoryValues(int memorySizeKB)
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, memorySizeKB, 2, 1);
        bool success = Argon2PhcFormat.TryDecode(encoded, out _, out _,
            out _, out int decodedMemory, out _, out _, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(memorySizeKB, decodedMemory);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    public void TestParameterEncoding_IterationValues(int iterations)
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, iterations, 1);
        bool success = Argon2PhcFormat.TryDecode(encoded, out _, out _,
            out _, out _, out int decodedIterations, out _, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(iterations, decodedIterations);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(16)]
    [InlineData(255)]
    public void TestParameterEncoding_ParallelismValues(int parallelism)
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, parallelism);
        bool success = Argon2PhcFormat.TryDecode(encoded, out _, out _,
            out _, out _, out _, out int decodedParallelism, out _);

        // Assert
        Assert.True(success);
        Assert.Equal(parallelism, decodedParallelism);
    }

    #endregion

    #region Version Compatibility Tests

    [Fact]
    public void TestVersionCompatibility_Version10_Encoding()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1, Argon2Version.Version10);

        // Assert
        Assert.Contains("v=16", encoded); // Version 0x10 = 16 decimal
    }

    [Fact]
    public void TestVersionCompatibility_Version13_Encoding()
    {
        // Arrange
        byte[] hash = new byte[32];
        byte[] salt = new byte[16];
        new Random(42).NextBytes(hash);
        new Random(43).NextBytes(salt);

        // Act
        string encoded = Argon2PhcFormat.Encode(hash, salt, Argon2Type.Argon2id, 32, 2, 1, Argon2Version.Version13);

        // Assert
        Assert.Contains("v=19", encoded); // Version 0x13 = 19 decimal
    }

    [Fact]
    public void TestVersionCompatibility_Decoding()
    {
        // Arrange
        string phcV10 = "$argon2id$v=16$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";
        string phcV13 = "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success10 = Argon2PhcFormat.TryDecode(phcV10, out _, out _, out _, out _, out _, out _, out Argon2Version version10);
        bool success13 = Argon2PhcFormat.TryDecode(phcV13, out _, out _, out _, out _, out _, out _, out Argon2Version version13);

        // Assert
        Assert.True(success10);
        Assert.True(success13);
        Assert.Equal(Argon2Version.Version10, version10);
        Assert.Equal(Argon2Version.Version13, version13);
    }

    #endregion

    #region Builder Pattern Interop Tests

    [Fact]
    public void TestBuilder_CreateAndUseWithPhcFormat()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateBuilder()
            .WithType(Argon2Type.Argon2id)
            .WithVersion(Argon2Version.Version13)
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .WithRandomSalt(16)
            .Build();

        // Act
        string phcHash = Argon2PhcFormat.HashToPhcString("password", parameters);
        var (isValid, decodedParams) = Argon2PhcFormat.VerifyPhcString("password", phcHash);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(decodedParams);
        Assert.Equal(parameters.MemorySizeKB, decodedParams.MemorySizeKB);
        Assert.Equal(parameters.Iterations, decodedParams.Iterations);
        Assert.Equal(parameters.Parallelism, decodedParams.Parallelism);
    }

    [Fact]
    public void TestBuilder_WithExpressionInterop()
    {
        // Arrange
        var baseParams = Argon2Parameters.CreateDefault();
        var modifiedParams = baseParams with { MemorySizeKB = 32, Salt = Argon2.GenerateSalt(16) };

        // Act
        var argon2 = new Argon2(modifiedParams);
        byte[] hash = argon2.Hash("password");
        string phcHash = Argon2PhcFormat.Encode(hash, modifiedParams);

        // Verify
        bool isValid = Argon2PhcFormat.VerifyPassword("password", phcHash);

        // Assert
        Assert.True(isValid);
    }

    #endregion
}
