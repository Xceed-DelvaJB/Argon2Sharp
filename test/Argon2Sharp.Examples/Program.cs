using Argon2Sharp;
using System.Text;

Console.WriteLine("=== Argon2Sharp - Pure C# Argon2 Implementation ===");
Console.WriteLine("Based on RFC 9106 Specification\n");

// Example 1: Basic password hashing with default parameters
Console.WriteLine("Example 1: Basic Password Hashing");
Console.WriteLine("----------------------------------");
string password = "MySecurePassword123!";
byte[] hash = Argon2.HashPassword(password, out byte[] salt);
Console.WriteLine($"Password: {password}");
Console.WriteLine($"Salt (Base64): {Convert.ToBase64String(salt)}");
Console.WriteLine($"Hash (Base64): {Convert.ToBase64String(hash)}");
Console.WriteLine($"Hash Length: {hash.Length} bytes\n");

// Example 2: Password verification
Console.WriteLine("Example 2: Password Verification");
Console.WriteLine("----------------------------------");
var parameters = Argon2Parameters.CreateDefault();
parameters.Salt = salt;
var argon2 = new Argon2(parameters);

bool isValid = argon2.Verify(password, hash);
Console.WriteLine($"Verification with correct password: {isValid}");

bool isInvalid = argon2.Verify("WrongPassword", hash);
Console.WriteLine($"Verification with wrong password: {isInvalid}\n");

// Example 3: Using PHC string format
Console.WriteLine("Example 3: PHC String Format");
Console.WriteLine("----------------------------------");
string phcHash = Argon2PhcFormat.HashPassword("SecurePassword", 
    memorySizeKB: 65536,  // 64 MB
    iterations: 3,
    parallelism: 4);
Console.WriteLine($"PHC Format Hash: {phcHash}");

bool phcValid = Argon2PhcFormat.VerifyPassword("SecurePassword", phcHash);
Console.WriteLine($"PHC Verification: {phcValid}\n");

// Example 4: Custom parameters (high security)
Console.WriteLine("Example 4: High Security Parameters");
Console.WriteLine("----------------------------------");
var highSecParams = Argon2Parameters.CreateHighSecurity();
highSecParams.Salt = Argon2.GenerateSalt(16);
var highSecArgon2 = new Argon2(highSecParams);

var startTime = DateTime.Now;
byte[] secureHash = highSecArgon2.Hash("VeryImportantPassword");
var elapsedTime = (DateTime.Now - startTime).TotalMilliseconds;

Console.WriteLine($"Memory: {highSecParams.MemorySizeKB} KB");
Console.WriteLine($"Iterations: {highSecParams.Iterations}");
Console.WriteLine($"Parallelism: {highSecParams.Parallelism}");
Console.WriteLine($"Hash computed in: {elapsedTime:F2} ms");
Console.WriteLine($"Hash (Base64): {Convert.ToBase64String(secureHash)}\n");

// Example 5: Different Argon2 types
Console.WriteLine("Example 5: Different Argon2 Types");
Console.WriteLine("----------------------------------");
byte[] testSalt = Argon2.GenerateSalt(16);
string testPassword = "TestPassword";

foreach (Argon2Type type in Enum.GetValues<Argon2Type>())
{
    var typeParams = new Argon2Parameters
    {
        Type = type,
        MemorySizeKB = 32,
        Iterations = 3,
        Parallelism = 4,
        HashLength = 32,
        Salt = testSalt
    };
    
    var typeArgon2 = new Argon2(typeParams);
    byte[] typeHash = typeArgon2.Hash(testPassword);
    Console.WriteLine($"{type}: {Convert.ToBase64String(typeHash)}");
}
Console.WriteLine();

// Example 6: Using secret key and associated data
Console.WriteLine("Example 6: Secret Key and Associated Data");
Console.WriteLine("----------------------------------");
var advancedParams = new Argon2Parameters
{
    Type = Argon2Type.Argon2id,
    MemorySizeKB = 32,
    Iterations = 3,
    Parallelism = 4,
    HashLength = 32,
    Salt = Argon2.GenerateSalt(16),
    Secret = Encoding.UTF8.GetBytes("my-application-secret-key"),
    AssociatedData = Encoding.UTF8.GetBytes("user-context-data")
};

var advancedArgon2 = new Argon2(advancedParams);
byte[] advancedHash = advancedArgon2.Hash("password");
Console.WriteLine($"Hash with secret and associated data:");
Console.WriteLine($"{Convert.ToBase64String(advancedHash)}\n");

// Example 7: Performance comparison
Console.WriteLine("Example 7: Performance Comparison");
Console.WriteLine("----------------------------------");
var testParams = new[] 
{
    ("Low Memory (32 KB)", new Argon2Parameters { MemorySizeKB = 32, Iterations = 3, Parallelism = 4, HashLength = 32, Salt = Argon2.GenerateSalt(16) }),
    ("Medium Memory (1 MB)", new Argon2Parameters { MemorySizeKB = 1024, Iterations = 3, Parallelism = 4, HashLength = 32, Salt = Argon2.GenerateSalt(16) }),
    ("High Memory (16 MB)", new Argon2Parameters { MemorySizeKB = 16384, Iterations = 3, Parallelism = 4, HashLength = 32, Salt = Argon2.GenerateSalt(16) })
};

string perfPassword = "BenchmarkPassword";
foreach (var (name, param) in testParams)
{
    var perfArgon2 = new Argon2(param);
    var perfStart = DateTime.Now;
    byte[] perfHash = perfArgon2.Hash(perfPassword);
    var perfElapsed = (DateTime.Now - perfStart).TotalMilliseconds;
    Console.WriteLine($"{name}: {perfElapsed:F2} ms");
}

Console.WriteLine("\n=== Examples completed successfully! ===");
