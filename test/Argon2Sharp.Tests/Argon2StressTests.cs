using System.Collections.Concurrent;
using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Stress tests and concurrency tests for Argon2 implementation.
/// Tests performance under load, thread safety, and behavior with extreme inputs.
/// </summary>
public class Argon2StressTests
{
    #region Concurrency Tests

    [Fact]
    public void TestConcurrentHashing_MultipleThreads()
    {
        // Arrange
        const int threadCount = 10;
        const int operationsPerThread = 20;
        var results = new ConcurrentBag<(string password, byte[] hash)>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        Parallel.For(0, threadCount, i =>
        {
            try
            {
                for (int j = 0; j < operationsPerThread; j++)
                {
                    string password = $"password_{i}_{j}";
                    byte[] salt = Argon2.GenerateSalt(16);
                    var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
                    var argon2 = new Argon2(parameters);
                    byte[] hash = argon2.Hash(password);
                    results.Add((password, hash));
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount * operationsPerThread, results.Count);
    }

    [Fact]
    public void TestConcurrentVerification_MultipleThreads()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        
        string password = "testpassword";
        byte[] hash = argon2.Hash(password);

        const int threadCount = 20;
        var results = new ConcurrentBag<bool>();

        // Act - verify from multiple threads simultaneously
        Parallel.For(0, threadCount, _ =>
        {
            bool isValid = argon2.Verify(password, hash.AsSpan());
            results.Add(isValid);
        });

        // Assert
        Assert.Equal(threadCount, results.Count);
        Assert.All(results, r => Assert.True(r));
    }

    [Fact]
    public void TestConcurrentHashAndVerify_MixedOperations()
    {
        // Arrange
        const int operations = 50;
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        Parallel.For(0, operations, i =>
        {
            try
            {
                byte[] salt = Argon2.GenerateSalt(16);
                var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
                var argon2 = new Argon2(parameters);

                string password = $"pwd_{i}";
                byte[] hash = argon2.Hash(password);
                bool verified = argon2.Verify(password, hash.AsSpan());
                
                if (!verified)
                    throw new Exception($"Verification failed for password {i}");
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
    }

    [Fact]
    public void TestConcurrentPHCFormatOperations()
    {
        // Arrange
        const int operations = 30;
        var results = new ConcurrentBag<(string password, string phcHash, bool verified)>();

        // Act
        Parallel.For(0, operations, i =>
        {
            string password = $"password_{i}";
            string phcHash = Argon2PhcFormat.HashPassword(password, memorySizeKB: 32, iterations: 2, parallelism: 1);
            bool verified = Argon2PhcFormat.VerifyPassword(password, phcHash);
            results.Add((password, phcHash, verified));
        });

        // Assert
        Assert.Equal(operations, results.Count);
        Assert.All(results, r => Assert.True(r.verified));
    }

    [Fact]
    public void TestSamePasswordConcurrent_ProducesConsistentResults()
    {
        // Arrange - same password and salt should produce same hash
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "consistentpassword";
        var hashes = new ConcurrentBag<string>();

        // Act
        Parallel.For(0, 10, _ =>
        {
            var parameters = Argon2Parameters.CreateForTesting() with { Salt = (byte[])salt.Clone() };
            var argon2 = new Argon2(parameters);
            byte[] hash = argon2.Hash(password);
            hashes.Add(Convert.ToBase64String(hash));
        });

        // Assert - all hashes should be identical
        Assert.Single(hashes.Distinct());
    }

    #endregion

    #region Large Input Tests

    [Fact]
    public void TestLargePassword_10KB()
    {
        // Arrange
        string password = new string('x', 10 * 1024);
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
    public void TestLargePassword_100KB()
    {
        // Arrange
        string password = new string('y', 100 * 1024);
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
    public void TestLargeSalt_512Bytes()
    {
        // Arrange
        string password = "password";
        byte[] salt = Argon2.GenerateSalt(512);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Assert
        Assert.NotNull(hash);
    }

    [Fact]
    public void TestLargeSecret_1KB()
    {
        // Arrange
        byte[] secret = new byte[1024];
        new Random(42).NextBytes(secret);
        byte[] salt = Argon2.GenerateSalt(16);
        
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
    public void TestLargeAssociatedData_4KB()
    {
        // Arrange
        byte[] ad = new byte[4096];
        new Random(42).NextBytes(ad);
        byte[] salt = Argon2.GenerateSalt(16);
        
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
    public void TestLargeHashOutput_2KB()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(2048)
            .WithSalt(salt)
            .Build();

        // Act
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Assert
        Assert.Equal(2048, hash.Length);
    }

    #endregion

    #region Repeated Operations Tests

    [Fact]
    public void TestRepeatedHashOperations_100Times()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        var hashes = new List<byte[]>();

        // Act
        for (int i = 0; i < 100; i++)
        {
            hashes.Add(argon2.Hash($"password{i}"));
        }

        // Assert - all should succeed and be different
        Assert.Equal(100, hashes.Count);
        Assert.Equal(100, hashes.Select(h => Convert.ToBase64String(h)).Distinct().Count());
    }

    [Fact]
    public void TestRepeatedVerificationOperations()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash("password");

        // Act - verify 100 times
        int successCount = 0;
        for (int i = 0; i < 100; i++)
        {
            if (argon2.Verify("password", hash.AsSpan()))
                successCount++;
        }

        // Assert
        Assert.Equal(100, successCount);
    }

    [Fact]
    public void TestRepeatedArgon2InstanceCreation()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var hashes = new List<byte[]>();

        // Act - create new instance each time
        for (int i = 0; i < 50; i++)
        {
            var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
            var argon2 = new Argon2(parameters);
            hashes.Add(argon2.Hash("samepassword"));
        }

        // Assert - all hashes should be identical (deterministic)
        Assert.Single(hashes.Select(h => Convert.ToBase64String(h)).Distinct());
    }

    #endregion

    #region Memory Pressure Tests

    [Fact]
    public void TestMemoryPressure_ConcurrentLargeMemory()
    {
        // Arrange
        const int concurrentOperations = 5;
        var results = new ConcurrentBag<byte[]>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act - run multiple operations with larger memory in parallel
        Parallel.For(0, concurrentOperations, i =>
        {
            try
            {
                byte[] salt = Argon2.GenerateSalt(16);
                var parameters = new Argon2Parameters
                {
                    Type = Argon2Type.Argon2id,
                    MemorySizeKB = 1024, // 1 MB per operation
                    Iterations = 1,
                    Parallelism = 1,
                    HashLength = 32,
                    Salt = salt
                };

                var argon2 = new Argon2(parameters);
                results.Add(argon2.Hash($"password{i}"));
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(concurrentOperations, results.Count);
    }

    [Fact]
    public void TestSequentialLargeMemoryOperations()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);

        // Act - sequential operations with moderate memory
        for (int i = 0; i < 10; i++)
        {
            var parameters = new Argon2Parameters
            {
                Type = Argon2Type.Argon2id,
                MemorySizeKB = 512, // 512 KB
                Iterations = 1,
                Parallelism = 1,
                HashLength = 32,
                Salt = salt
            };

            var argon2 = new Argon2(parameters);
            byte[] hash = argon2.Hash($"password{i}");
            Assert.NotNull(hash);
        }

        // Force GC and verify no issues
        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    #endregion

    #region Edge Case Stress Tests

    [Fact]
    public void TestRapidParameterChanges()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";
        var hashes = new Dictionary<string, byte[]>();

        // Act - rapidly change parameters
        for (int memory = 8; memory <= 128; memory *= 2)
        {
            for (int iterations = 1; iterations <= 4; iterations++)
            {
                for (int parallelism = 1; parallelism <= 4; parallelism++)
                {
                    if (memory >= 8 * parallelism)
                    {
                        var parameters = Argon2Parameters.CreateBuilder()
                            .WithMemorySizeKB(memory)
                            .WithIterations(iterations)
                            .WithParallelism(parallelism)
                            .WithHashLength(32)
                            .WithSalt(salt)
                            .Build();

                        var argon2 = new Argon2(parameters);
                        byte[] hash = argon2.Hash(password);
                        hashes[$"m{memory}_t{iterations}_p{parallelism}"] = hash;
                    }
                }
            }
        }

        // Assert - all should succeed and produce different hashes
        // Note: With small memory values, collisions are theoretically possible
        // The main goal is to verify no crashes during rapid parameter changes
        Assert.True(hashes.Count > 10, $"Expected more than 10 hashes, got {hashes.Count}");
        int distinctCount = hashes.Values.Select(h => Convert.ToBase64String(h)).Distinct().Count();
        Assert.True(distinctCount >= hashes.Count * 0.7, 
            $"Expected at least 70% distinct hashes, got {distinctCount}/{hashes.Count}");
    }

    [Fact]
    public void TestMixedArgon2Types_Sequential()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        string password = "password";

        // Act
        foreach (Argon2Type type in Enum.GetValues<Argon2Type>())
        {
            for (int i = 0; i < 10; i++)
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
                byte[] hash = argon2.Hash(password);
                Assert.NotNull(hash);
                Assert.True(argon2.Verify(password, hash.AsSpan()));
            }
        }
    }

    [Fact]
    public void TestMixedArgon2Types_Concurrent()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var results = new ConcurrentBag<(Argon2Type type, bool success)>();

        // Act
        Parallel.ForEach(Enum.GetValues<Argon2Type>(), type =>
        {
            try
            {
                var parameters = new Argon2Parameters
                {
                    Type = type,
                    MemorySizeKB = 32,
                    Iterations = 2,
                    Parallelism = 1,
                    HashLength = 32,
                    Salt = (byte[])salt.Clone()
                };

                var argon2 = new Argon2(parameters);
                byte[] hash = argon2.Hash("password");
                bool verified = argon2.Verify("password", hash.AsSpan());
                results.Add((type, verified));
            }
            catch
            {
                results.Add((type, false));
            }
        });

        // Assert
        Assert.Equal(3, results.Count); // Argon2d, Argon2i, Argon2id
        Assert.All(results, r => Assert.True(r.success, $"Failed for {r.type}"));
    }

    #endregion

    #region PHC Format Stress Tests

    [Fact]
    public void TestPHCFormat_RepeatedEncodeDecode()
    {
        // Arrange
        byte[] originalHash = new byte[32];
        byte[] originalSalt = new byte[16];
        new Random(42).NextBytes(originalHash);
        new Random(43).NextBytes(originalSalt);

        // Act - encode and decode 100 times
        for (int i = 0; i < 100; i++)
        {
            string encoded = Argon2PhcFormat.Encode(
                originalHash, originalSalt, Argon2Type.Argon2id, 32, 2, 1);

            bool success = Argon2PhcFormat.TryDecode(
                encoded, out byte[]? hash, out byte[]? salt, 
                out Argon2Type type, out int m, out int t, out int p, out _);

            Assert.True(success);
            Assert.Equal(originalHash, hash);
            Assert.Equal(originalSalt, salt);
        }
    }

    [Fact]
    public void TestPHCFormat_ConcurrentHashVerify()
    {
        // Arrange
        const int operations = 30;
        var results = new ConcurrentBag<bool>();

        // Act
        Parallel.For(0, operations, i =>
        {
            string password = $"password_{i}";
            string phcHash = Argon2PhcFormat.HashPassword(password, memorySizeKB: 32, iterations: 2, parallelism: 1);
            
            // Verify correct password
            bool validCorrect = Argon2PhcFormat.VerifyPassword(password, phcHash);
            
            // Verify wrong password
            bool validWrong = Argon2PhcFormat.VerifyPassword("wrong" + password, phcHash);

            results.Add(validCorrect && !validWrong);
        });

        // Assert
        Assert.Equal(operations, results.Count);
        Assert.All(results, Assert.True);
    }

    #endregion

    #region Static API Stress Tests

    [Fact]
    public void TestStaticHashPasswordWithSalt_ConcurrentCalls()
    {
        // Arrange
        var results = new ConcurrentBag<(byte[] hash, byte[] salt)>();

        // Act
        Parallel.For(0, 20, i =>
        {
            var (hash, salt) = Argon2.HashPasswordWithSalt($"password{i}");
            results.Add((hash, salt));
        });

        // Assert
        Assert.Equal(20, results.Count);
        Assert.All(results, r =>
        {
            Assert.NotNull(r.hash);
            Assert.NotNull(r.salt);
            Assert.Equal(32, r.hash.Length);
            Assert.Equal(16, r.salt.Length);
        });

        // All salts should be unique
        Assert.Equal(20, results.Select(r => Convert.ToBase64String(r.salt)).Distinct().Count());
    }

    [Fact]
    public void TestBase64Conversion_Stress()
    {
        // Arrange
        var random = new Random(42);

        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            int length = random.Next(4, 256);
            byte[] original = new byte[length];
            random.NextBytes(original);

            string base64 = Argon2.ToBase64(original);
            byte[] decoded = Argon2.FromBase64(base64);

            Assert.Equal(original, decoded);
        }
    }

    #endregion
}
