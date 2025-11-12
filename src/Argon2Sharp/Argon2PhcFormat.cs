using System.Text;

namespace Argon2Sharp;

/// <summary>
/// PHC string format encoder/decoder for Argon2.
/// Format: $argon2{type}$v={version}$m={memory},t={iterations},p={parallelism}$salt$hash
/// </summary>
public static class Argon2PhcFormat
{
    /// <summary>
    /// Encodes hash, salt, and parameters into PHC format string.
    /// Example: $argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhlcmU
    /// </summary>
    public static string Encode(
        byte[] hash,
        byte[] salt,
        Argon2Type type,
        int memorySizeKB,
        int iterations,
        int parallelism,
        Argon2Version version = Argon2Version.Version13)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(salt);

        string typeStr = type switch
        {
            Argon2Type.Argon2d => "argon2d",
            Argon2Type.Argon2i => "argon2i",
            Argon2Type.Argon2id => "argon2id",
            _ => throw new ArgumentException("Invalid Argon2 type", nameof(type))
        };

        string versionStr = ((int)version).ToString();
        string saltB64 = Convert.ToBase64String(salt).TrimEnd('=');
        string hashB64 = Convert.ToBase64String(hash).TrimEnd('=');

        return $"${typeStr}$v={versionStr}$m={memorySizeKB},t={iterations},p={parallelism}${saltB64}${hashB64}";
    }

    /// <summary>
    /// Decodes a PHC format string into its components.
    /// </summary>
    public static bool TryDecode(
        string phcString,
        out byte[]? hash,
        out byte[]? salt,
        out Argon2Type type,
        out int memorySizeKB,
        out int iterations,
        out int parallelism,
        out Argon2Version version)
    {
        hash = null;
        salt = null;
        type = Argon2Type.Argon2id;
        memorySizeKB = 0;
        iterations = 0;
        parallelism = 0;
        version = Argon2Version.Version13;

        if (string.IsNullOrEmpty(phcString))
            return false;

        string[] parts = phcString.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 5)
            return false;

        // Parse type
        type = parts[0] switch
        {
            "argon2d" => Argon2Type.Argon2d,
            "argon2i" => Argon2Type.Argon2i,
            "argon2id" => Argon2Type.Argon2id,
            _ => throw new FormatException($"Unknown Argon2 type: {parts[0]}")
        };

        // Parse version
        if (parts[1].StartsWith("v="))
        {
            if (!int.TryParse(parts[1][2..], out int v))
                return false;
            version = (Argon2Version)v;
        }
        else
        {
            return false;
        }

        // Parse parameters
        string[] parameters = parts[2].Split(',');
        if (parameters.Length != 3)
            return false;

        foreach (string param in parameters)
        {
            string[] kv = param.Split('=');
            if (kv.Length != 2)
                return false;

            switch (kv[0])
            {
                case "m":
                    if (!int.TryParse(kv[1], out memorySizeKB))
                        return false;
                    break;
                case "t":
                    if (!int.TryParse(kv[1], out iterations))
                        return false;
                    break;
                case "p":
                    if (!int.TryParse(kv[1], out parallelism))
                        return false;
                    break;
                default:
                    return false;
            }
        }

        // Parse salt
        try
        {
            string saltB64 = parts[3];
            // Add padding if needed
            int padding = (4 - (saltB64.Length % 4)) % 4;
            saltB64 += new string('=', padding);
            salt = Convert.FromBase64String(saltB64);
        }
        catch
        {
            return false;
        }

        // Parse hash
        try
        {
            string hashB64 = parts[4];
            // Add padding if needed
            int padding = (4 - (hashB64.Length % 4)) % 4;
            hashB64 += new string('=', padding);
            hash = Convert.FromBase64String(hashB64);
        }
        catch
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Hashes a password and returns PHC format string with generated salt.
    /// </summary>
    public static string HashPassword(
        string password,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        int hashLength = 32,
        Argon2Type type = Argon2Type.Argon2id)
    {
        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = new Argon2Parameters
        {
            Type = type,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hashLength,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        return Encode(hash, salt, type, memorySizeKB, iterations, parallelism);
    }

    /// <summary>
    /// Verifies a password against a PHC format hash string.
    /// </summary>
    public static bool VerifyPassword(string password, string phcHash)
    {
        if (!TryDecode(phcHash, out byte[]? hash, out byte[]? salt, out Argon2Type type,
            out int memorySizeKB, out int iterations, out int parallelism, out Argon2Version version))
        {
            return false;
        }

        if (hash == null || salt == null)
            return false;

        var parameters = new Argon2Parameters
        {
            Type = type,
            Version = version,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hash.Length,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        return argon2.Verify(password, hash);
    }
}
