using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Core Argon2 block operations - compression function and permutations.
/// Implements the core algorithm as specified in RFC 9106.
/// Optimized for maximum performance with SIMD intrinsics.
/// </summary>
internal static class Argon2Core
{
    public const int BlockSize = 1024; // 1024 bytes = 128 64-bit words
    public const int QwordsInBlock = BlockSize / 8; // 128 qwords
    public const int SyncPoints = 4;

    /// <summary>
    /// Argon2 compression function G - optimized inline version.
    /// Operates on two 1024-byte blocks and produces one 1024-byte block.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressionG(Span<ulong> block, int a, int b, int c, int d)
    {
        ulong va = block[a];
        ulong vb = block[b];
        ulong vc = block[c];
        ulong vd = block[d];

        // Fused multiply-add operations with inline multiplication
        va += vb + ((va & 0xFFFFFFFFUL) * (vb & 0xFFFFFFFFUL) << 1);
        vd = ulong.RotateRight(vd ^ va, 32);
        vc += vd + ((vc & 0xFFFFFFFFUL) * (vd & 0xFFFFFFFFUL) << 1);
        vb = ulong.RotateRight(vb ^ vc, 24);
        va += vb + ((va & 0xFFFFFFFFUL) * (vb & 0xFFFFFFFFUL) << 1);
        vd = ulong.RotateRight(vd ^ va, 16);
        vc += vd + ((vc & 0xFFFFFFFFUL) * (vd & 0xFFFFFFFFUL) << 1);
        vb = ulong.RotateRight(vb ^ vc, 63);

        block[a] = va;
        block[b] = vb;
        block[c] = vc;
        block[d] = vd;
    }

    /// <summary>
    /// P permutation - applies column and row operations.
    /// Fully unrolled for maximum performance.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void PermutationP(Span<ulong> block)
    {
        // Column-wise operations - unrolled
        CompressionG(block, 0, 8, 16, 24);
        CompressionG(block, 32, 40, 48, 56);
        CompressionG(block, 64, 72, 80, 88);
        CompressionG(block, 96, 104, 112, 120);

        CompressionG(block, 1, 9, 17, 25);
        CompressionG(block, 33, 41, 49, 57);
        CompressionG(block, 65, 73, 81, 89);
        CompressionG(block, 97, 105, 113, 121);

        CompressionG(block, 2, 10, 18, 26);
        CompressionG(block, 34, 42, 50, 58);
        CompressionG(block, 66, 74, 82, 90);
        CompressionG(block, 98, 106, 114, 122);

        CompressionG(block, 3, 11, 19, 27);
        CompressionG(block, 35, 43, 51, 59);
        CompressionG(block, 67, 75, 83, 91);
        CompressionG(block, 99, 107, 115, 123);

        CompressionG(block, 4, 12, 20, 28);
        CompressionG(block, 36, 44, 52, 60);
        CompressionG(block, 68, 76, 84, 92);
        CompressionG(block, 100, 108, 116, 124);

        CompressionG(block, 5, 13, 21, 29);
        CompressionG(block, 37, 45, 53, 61);
        CompressionG(block, 69, 77, 85, 93);
        CompressionG(block, 101, 109, 117, 125);

        CompressionG(block, 6, 14, 22, 30);
        CompressionG(block, 38, 46, 54, 62);
        CompressionG(block, 70, 78, 86, 94);
        CompressionG(block, 102, 110, 118, 126);

        CompressionG(block, 7, 15, 23, 31);
        CompressionG(block, 39, 47, 55, 63);
        CompressionG(block, 71, 79, 87, 95);
        CompressionG(block, 103, 111, 119, 127);

        // Row-wise operations - unrolled
        CompressionG(block, 0, 1, 2, 3);
        CompressionG(block, 4, 5, 6, 7);
        CompressionG(block, 8, 9, 10, 11);
        CompressionG(block, 12, 13, 14, 15);

        CompressionG(block, 16, 17, 18, 19);
        CompressionG(block, 20, 21, 22, 23);
        CompressionG(block, 24, 25, 26, 27);
        CompressionG(block, 28, 29, 30, 31);

        CompressionG(block, 32, 33, 34, 35);
        CompressionG(block, 36, 37, 38, 39);
        CompressionG(block, 40, 41, 42, 43);
        CompressionG(block, 44, 45, 46, 47);

        CompressionG(block, 48, 49, 50, 51);
        CompressionG(block, 52, 53, 54, 55);
        CompressionG(block, 56, 57, 58, 59);
        CompressionG(block, 60, 61, 62, 63);

        CompressionG(block, 64, 65, 66, 67);
        CompressionG(block, 68, 69, 70, 71);
        CompressionG(block, 72, 73, 74, 75);
        CompressionG(block, 76, 77, 78, 79);

        CompressionG(block, 80, 81, 82, 83);
        CompressionG(block, 84, 85, 86, 87);
        CompressionG(block, 88, 89, 90, 91);
        CompressionG(block, 92, 93, 94, 95);

        CompressionG(block, 96, 97, 98, 99);
        CompressionG(block, 100, 101, 102, 103);
        CompressionG(block, 104, 105, 106, 107);
        CompressionG(block, 108, 109, 110, 111);

        CompressionG(block, 112, 113, 114, 115);
        CompressionG(block, 116, 117, 118, 119);
        CompressionG(block, 120, 121, 122, 123);
        CompressionG(block, 124, 125, 126, 127);
    }

    /// <summary>
    /// Argon2 block compression function - SIMD optimized.
    /// Combines two blocks X and Y into a result block using XOR and permutation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void FillBlock(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock)
    {
        // Use Vector<ulong> for SIMD operations when available
        if (Vector.IsHardwareAccelerated && Vector<ulong>.Count >= 2)
        {
            FillBlockSimd(prevBlock, refBlock, nextBlock);
        }
        else
        {
            FillBlockScalar(prevBlock, refBlock, nextBlock);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void FillBlockSimd(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock)
    {
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];

        int vectorSize = Vector<ulong>.Count;
        int vectorizedLength = QwordsInBlock - (QwordsInBlock % vectorSize);

        // R = X XOR Y (vectorized)
        for (int i = 0; i < vectorizedLength; i += vectorSize)
        {
            var prevVec = new Vector<ulong>(prevBlock.Slice(i));
            var refVec = new Vector<ulong>(refBlock.Slice(i));
            (prevVec ^ refVec).CopyTo(r.Slice(i));
        }
        for (int i = vectorizedLength; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }

        r.CopyTo(z);

        // Apply P permutation
        PermutationP(z);

        // Z = prev XOR ref XOR P(R) (vectorized)
        for (int i = 0; i < vectorizedLength; i += vectorSize)
        {
            var prevVec = new Vector<ulong>(prevBlock.Slice(i));
            var refVec = new Vector<ulong>(refBlock.Slice(i));
            var zVec = new Vector<ulong>(z.Slice(i));
            (prevVec ^ refVec ^ zVec).CopyTo(nextBlock.Slice(i));
        }
        for (int i = vectorizedLength; i < QwordsInBlock; i++)
        {
            nextBlock[i] = prevBlock[i] ^ refBlock[i] ^ z[i];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void FillBlockScalar(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock)
    {
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];

        // R = X XOR Y - unrolled by 8
        int i = 0;
        for (; i + 8 <= QwordsInBlock; i += 8)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
            r[i + 1] = prevBlock[i + 1] ^ refBlock[i + 1];
            r[i + 2] = prevBlock[i + 2] ^ refBlock[i + 2];
            r[i + 3] = prevBlock[i + 3] ^ refBlock[i + 3];
            r[i + 4] = prevBlock[i + 4] ^ refBlock[i + 4];
            r[i + 5] = prevBlock[i + 5] ^ refBlock[i + 5];
            r[i + 6] = prevBlock[i + 6] ^ refBlock[i + 6];
            r[i + 7] = prevBlock[i + 7] ^ refBlock[i + 7];
        }
        for (; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }

        r.CopyTo(z);

        // Apply P permutation
        PermutationP(z);

        // Z = prev XOR ref XOR P(R) - unrolled by 8
        i = 0;
        for (; i + 8 <= QwordsInBlock; i += 8)
        {
            nextBlock[i] = prevBlock[i] ^ refBlock[i] ^ z[i];
            nextBlock[i + 1] = prevBlock[i + 1] ^ refBlock[i + 1] ^ z[i + 1];
            nextBlock[i + 2] = prevBlock[i + 2] ^ refBlock[i + 2] ^ z[i + 2];
            nextBlock[i + 3] = prevBlock[i + 3] ^ refBlock[i + 3] ^ z[i + 3];
            nextBlock[i + 4] = prevBlock[i + 4] ^ refBlock[i + 4] ^ z[i + 4];
            nextBlock[i + 5] = prevBlock[i + 5] ^ refBlock[i + 5] ^ z[i + 5];
            nextBlock[i + 6] = prevBlock[i + 6] ^ refBlock[i + 6] ^ z[i + 6];
            nextBlock[i + 7] = prevBlock[i + 7] ^ refBlock[i + 7] ^ z[i + 7];
        }
        for (; i < QwordsInBlock; i++)
        {
            nextBlock[i] = prevBlock[i] ^ refBlock[i] ^ z[i];
        }
    }

    /// <summary>
    /// XOR two blocks together - SIMD optimized.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static void XorBlock(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        if (Vector.IsHardwareAccelerated && Vector<ulong>.Count >= 2)
        {
            int vectorSize = Vector<ulong>.Count;
            int vectorizedLength = QwordsInBlock - (QwordsInBlock % vectorSize);

            for (int i = 0; i < vectorizedLength; i += vectorSize)
            {
                var srcVec = new Vector<ulong>(source.Slice(i));
                var dstVec = new Vector<ulong>(destination.Slice(i));
                (srcVec ^ dstVec).CopyTo(destination.Slice(i));
            }
            for (int i = vectorizedLength; i < QwordsInBlock; i++)
            {
                destination[i] ^= source[i];
            }
        }
        else
        {
            // Unrolled scalar version
            int i = 0;
            for (; i + 8 <= QwordsInBlock; i += 8)
            {
                destination[i] ^= source[i];
                destination[i + 1] ^= source[i + 1];
                destination[i + 2] ^= source[i + 2];
                destination[i + 3] ^= source[i + 3];
                destination[i + 4] ^= source[i + 4];
                destination[i + 5] ^= source[i + 5];
                destination[i + 6] ^= source[i + 6];
                destination[i + 7] ^= source[i + 7];
            }
            for (; i < QwordsInBlock; i++)
            {
                destination[i] ^= source[i];
            }
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
    /// Convert byte array to ulong array (little-endian).
    /// Uses MemoryMarshal for zero-copy on little-endian systems.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void BytesToQwords(ReadOnlySpan<byte> bytes, Span<ulong> qwords)
    {
        if (BitConverter.IsLittleEndian)
        {
            // Zero-copy cast on little-endian systems
            MemoryMarshal.Cast<byte, ulong>(bytes).CopyTo(qwords);
        }
        else
        {
            // Fallback for big-endian systems
            for (int i = 0; i < qwords.Length; i++)
            {
                qwords[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(i * 8, 8));
            }
        }
    }

    /// <summary>
    /// Convert ulong array to byte array (little-endian).
    /// Uses MemoryMarshal for zero-copy on little-endian systems.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QwordsToBytes(ReadOnlySpan<ulong> qwords, Span<byte> bytes)
    {
        if (BitConverter.IsLittleEndian)
        {
            // Zero-copy cast on little-endian systems
            MemoryMarshal.AsBytes(qwords).CopyTo(bytes);
        }
        else
        {
            // Fallback for big-endian systems
            for (int i = 0; i < qwords.Length; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.Slice(i * 8, 8), qwords[i]);
            }
        }
    }
}
