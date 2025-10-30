using System.Runtime.CompilerServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Core Argon2 block operations - compression function and permutations.
/// Implements the core algorithm as specified in RFC 9106.
/// </summary>
internal static class Argon2Core
{
    public const int BlockSize = 1024; // 1024 bytes = 128 64-bit words
    public const int QwordsInBlock = BlockSize / 8; // 128 qwords
    public const int SyncPoints = 4;

    /// <summary>
    /// Argon2 compression function G.
    /// Operates on two 1024-byte blocks and produces one 1024-byte block.
    /// </summary>
    public static void CompressionG(Span<ulong> block, int a, int b, int c, int d)
    {
        ulong va = block[a];
        ulong vb = block[b];
        ulong vc = block[c];
        ulong vd = block[d];

        va = va + vb + 2 * Mul32(va, vb);
        vd = RotateRight(vd ^ va, 32);
        vc = vc + vd + 2 * Mul32(vc, vd);
        vb = RotateRight(vb ^ vc, 24);
        va = va + vb + 2 * Mul32(va, vb);
        vd = RotateRight(vd ^ va, 16);
        vc = vc + vd + 2 * Mul32(vc, vd);
        vb = RotateRight(vb ^ vc, 63);

        block[a] = va;
        block[b] = vb;
        block[c] = vc;
        block[d] = vd;
    }

    /// <summary>
    /// P permutation - applies column and row operations.
    /// </summary>
    public static void PermutationP(Span<ulong> block)
    {
        // Column-wise operation
        for (int i = 0; i < 8; i++)
        {
            CompressionG(block, i, i + 8, i + 16, i + 24);
            CompressionG(block, i + 32, i + 40, i + 48, i + 56);
            CompressionG(block, i + 64, i + 72, i + 80, i + 88);
            CompressionG(block, i + 96, i + 104, i + 112, i + 120);
        }

        // Row-wise operation
        for (int i = 0; i < 8; i++)
        {
            int row = i * 16;
            CompressionG(block, row, row + 1, row + 2, row + 3);
            CompressionG(block, row + 4, row + 5, row + 6, row + 7);
            CompressionG(block, row + 8, row + 9, row + 10, row + 11);
            CompressionG(block, row + 12, row + 13, row + 14, row + 15);
        }
    }

    /// <summary>
    /// Argon2 block compression function.
    /// Combines two blocks X and Y into a result block using XOR and permutation.
    /// </summary>
    public static void FillBlock(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock)
    {
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];

        // R = X XOR Y
        for (int i = 0; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }

        r.CopyTo(z);

        // Apply P permutation
        PermutationP(z);

        // Z = P(R) XOR R
        for (int i = 0; i < QwordsInBlock; i++)
        {
            nextBlock[i] = prevBlock[i] ^ refBlock[i] ^ z[i];
        }
    }

    /// <summary>
    /// XOR two blocks together.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void XorBlock(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        for (int i = 0; i < QwordsInBlock; i++)
        {
            destination[i] ^= source[i];
        }
    }

    /// <summary>
    /// Copy a block.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CopyBlock(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        source.CopyTo(destination);
    }

    /// <summary>
    /// Multiply lower 32 bits of two 64-bit words as unsigned 32-bit integers.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Mul32(ulong x, ulong y)
    {
        return (x & 0xFFFFFFFFUL) * (y & 0xFFFFFFFFUL);
    }

    /// <summary>
    /// Rotate right operation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong RotateRight(ulong value, int bits)
    {
        return (value >> bits) | (value << (64 - bits));
    }

    /// <summary>
    /// Convert byte array to ulong array (little-endian).
    /// </summary>
    public static void BytesToQwords(ReadOnlySpan<byte> bytes, Span<ulong> qwords)
    {
        for (int i = 0; i < qwords.Length; i++)
        {
            qwords[i] = BitConverter.ToUInt64(bytes.Slice(i * 8, 8));
        }
    }

    /// <summary>
    /// Convert ulong array to byte array (little-endian).
    /// </summary>
    public static void QwordsToBytes(ReadOnlySpan<ulong> qwords, Span<byte> bytes)
    {
        for (int i = 0; i < qwords.Length; i++)
        {
            BitConverter.TryWriteBytes(bytes.Slice(i * 8, 8), qwords[i]);
        }
    }
}
