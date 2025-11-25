# Migration Guide: v2.x to v3.0

This guide helps you migrate from Argon2Sharp v2.x to v3.0.

## Breaking Changes

### Argon2Parameters is now immutable

**v2.x (mutable):**
```csharp
var parameters = new Argon2Parameters();
parameters.MemorySizeKB = 65536;
parameters.Iterations = 4;
parameters.Salt = salt;
```

**v3.0 (immutable record):**
```csharp
// Option 1: Object initializer
var parameters = new Argon2Parameters
{
    MemorySizeKB = 65536,
    Iterations = 4,
    Salt = salt
};

// Option 2: Builder pattern (recommended)
var parameters = Argon2Parameters.CreateBuilder()
    .WithMemorySizeKB(65536)
    .WithIterations(4)
    .WithSalt(salt)
    .Build();

// Option 3: Modify existing with 'with' expression
var modified = parameters with { Salt = newSalt };
```

## API Changes

### Hash methods

**v2.x:**
```csharp
byte[] hash = argon2.Hash(passwordBytes);
```

**v3.0 (Span-based, more efficient):**
```csharp
byte[] hash = argon2.Hash(passwordBytes.AsSpan());
// or
byte[] hash = argon2.Hash("password"); // string overload unchanged
```

### HashPassword with salt output

**v2.x:**
```csharp
byte[] hash = Argon2.HashPassword("password", out byte[] salt);
```

**v3.0 (tuple return):**
```csharp
var (hash, salt) = Argon2.HashPasswordWithSalt("password");
```

### PHC Format methods

**v2.x:**
```csharp
string phcHash = Argon2PhcFormat.HashPassword("password", memorySizeKB, iterations, parallelism, hashLength, type);
bool isValid = Argon2PhcFormat.VerifyPassword("password", phcHash);
```

**v3.0:**
```csharp
// With auto-generated salt
string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("password");

// With custom parameters
var parameters = Argon2Parameters.CreateBuilder()
    .WithMemorySizeKB(65536)
    .WithRandomSalt()
    .Build();
string phcHash = Argon2PhcFormat.HashToPhcString("password", parameters);

// Verification with extracted parameters
var (isValid, extractedParams) = Argon2PhcFormat.VerifyPhcString("password", phcHash);
```

### Verify methods

**v2.x:**
```csharp
bool isValid = argon2.Verify("password", hashBytes);
```

**v3.0 (Span-based):**
```csharp
bool isValid = argon2.Verify("password", hashBytes.AsSpan());
```

## Builder Pattern

The new Builder pattern provides validation at construction time:

```csharp
var parameters = Argon2Parameters.CreateBuilder()
    .WithType(Argon2Type.Argon2id)
    .WithVersion(Argon2Version.Version13)
    .WithMemorySizeKB(65536)
    .WithIterations(4)
    .WithParallelism(4)
    .WithHashLength(32)
    .WithRandomSalt(16)  // Generates random salt
    .WithSecret(secretKey)  // Optional
    .WithAssociatedData(context)  // Optional
    .Build();  // Validates and creates immutable instance
```

## Deprecated Methods

The following methods are deprecated and will be removed in v4.0:

| Deprecated | Replacement |
|------------|-------------|
| `Argon2.Hash(byte[])` | `Hash(ReadOnlySpan<byte>)` |
| `Argon2.Verify(byte[], byte[])` | `Verify(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` |
| `Argon2.HashPassword(string, out byte[])` | `HashPasswordWithSalt(string)` |
| `Argon2PhcFormat.HashPassword(...)` | `HashToPhcString()` or `HashToPhcStringWithAutoSalt()` |
| `Argon2PhcFormat.VerifyPassword(...)` | `VerifyPhcString()` |
| `Argon2Parameters.Clone()` | Use `with` expression |

## Performance Improvements

v3.0 includes several performance optimizations:

1. **BinaryPrimitives**: Replaced `BitConverter` with `BinaryPrimitives` for faster byte/integer conversions
2. **MemoryMarshal.Cast**: Zero-copy conversions on little-endian systems
3. **CryptographicOperations.ZeroMemory**: Secure and efficient memory clearing
4. **Span<T> API**: Reduced allocations in hot paths

## Recommendations

1. **Use the Builder pattern** for creating parameters - it provides validation and a clean fluent API
2. **Use Span-based methods** for best performance
3. **Use tuple returns** (`HashPasswordWithSalt`, `VerifyPhcString`) for cleaner code
4. **Prefer `HashToPhcStringWithAutoSalt`** when you don't need custom parameters
