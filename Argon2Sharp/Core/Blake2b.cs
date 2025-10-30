using System.Runtime.CompilerServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Pure C# implementation of Blake2b-512 hash function used internally by Argon2.
/// Based on RFC 7693 specification.
/// </summary>
internal static class Blake2b
{
    private const int BlockSizeInBytes = 128;
    private const int HashSizeInBytes = 64;
    
    // Blake2b IV constants
    private static ReadOnlySpan<ulong> IV =>
    [
        0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL,
        0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
        0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL,
        0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
    ];
    
    // Blake2b sigma permutation table
    private static ReadOnlySpan<byte> Sigma =>
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    ];

    /// <summary>
    /// Computes Blake2b-512 hash of the input data.
    /// </summary>
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != HashSizeInBytes)
            throw new ArgumentException($"Output buffer must be {HashSizeInBytes} bytes", nameof(output));

        Span<ulong> h = stackalloc ulong[8];
        IV.CopyTo(h);
        h[0] ^= 0x01010000UL ^ (uint)HashSizeInBytes;

        Span<ulong> m = stackalloc ulong[16];
        ulong t0 = 0, t1 = 0;
        int remaining = input.Length;
        int offset = 0;

        while (remaining > BlockSizeInBytes)
        {
            t0 += BlockSizeInBytes;
            if (t0 < BlockSizeInBytes)
                t1++;

            LoadMessage(input.Slice(offset, BlockSizeInBytes), m);
            Compress(h, m, t0, t1, false);

            offset += BlockSizeInBytes;
            remaining -= BlockSizeInBytes;
        }

        // Final block
        t0 += (uint)remaining;
        if (t0 < remaining)
            t1++;

        Span<byte> lastBlock = stackalloc byte[BlockSizeInBytes];
        input.Slice(offset, remaining).CopyTo(lastBlock);
        lastBlock.Slice(remaining).Clear();

        LoadMessage(lastBlock, m);
        Compress(h, m, t0, t1, true);

        // Output hash
        for (int i = 0; i < 8; i++)
        {
            BitConverter.TryWriteBytes(output.Slice(i * 8, 8), h[i]);
        }
    }

    /// <summary>
    /// Blake2b long hash function for Argon2 - produces variable-length output.
    /// </summary>
    public static void LongHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int outLen = output.Length;

        if (outLen <= HashSizeInBytes)
        {
            Hash(input, output);
            return;
        }

        Span<byte> outLenBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(outLenBytes, (uint)outLen);

        Span<byte> firstBlock = stackalloc byte[input.Length + 4];
        outLenBytes.CopyTo(firstBlock);
        input.CopyTo(firstBlock.Slice(4));

        Span<byte> hash = stackalloc byte[HashSizeInBytes];
        Hash(firstBlock, hash);

        int written = Math.Min(HashSizeInBytes / 2, outLen);
        hash.Slice(0, written).CopyTo(output);

        int remaining = outLen - written;
        int pos = written;

        while (remaining > HashSizeInBytes / 2)
        {
            Hash(hash, hash);
            hash.Slice(0, HashSizeInBytes / 2).CopyTo(output.Slice(pos));
            pos += HashSizeInBytes / 2;
            remaining -= HashSizeInBytes / 2;
        }

        if (remaining > 0)
        {
            Hash(hash, hash);
            hash.Slice(0, remaining).CopyTo(output.Slice(pos));
        }
    }

    private static void LoadMessage(ReadOnlySpan<byte> block, Span<ulong> m)
    {
        for (int i = 0; i < 16; i++)
        {
            m[i] = BitConverter.ToUInt64(block.Slice(i * 8, 8));
        }
    }

    private static void Compress(Span<ulong> h, Span<ulong> m, ulong t0, ulong t1, bool isLastBlock)
    {
        Span<ulong> v = stackalloc ulong[16];

        // Initialize working variables
        h.CopyTo(v);
        IV.CopyTo(v.Slice(8));

        v[12] ^= t0;
        v[13] ^= t1;

        if (isLastBlock)
            v[14] = ~v[14];

        // 12 rounds
        for (int round = 0; round < 12; round++)
        {
            int sigmaOffset = round * 16;

            // Column step
            G(v, 0, 4, 8, 12, m[Sigma[sigmaOffset + 0]], m[Sigma[sigmaOffset + 1]]);
            G(v, 1, 5, 9, 13, m[Sigma[sigmaOffset + 2]], m[Sigma[sigmaOffset + 3]]);
            G(v, 2, 6, 10, 14, m[Sigma[sigmaOffset + 4]], m[Sigma[sigmaOffset + 5]]);
            G(v, 3, 7, 11, 15, m[Sigma[sigmaOffset + 6]], m[Sigma[sigmaOffset + 7]]);

            // Diagonal step
            G(v, 0, 5, 10, 15, m[Sigma[sigmaOffset + 8]], m[Sigma[sigmaOffset + 9]]);
            G(v, 1, 6, 11, 12, m[Sigma[sigmaOffset + 10]], m[Sigma[sigmaOffset + 11]]);
            G(v, 2, 7, 8, 13, m[Sigma[sigmaOffset + 12]], m[Sigma[sigmaOffset + 13]]);
            G(v, 3, 4, 9, 14, m[Sigma[sigmaOffset + 14]], m[Sigma[sigmaOffset + 15]]);
        }

        // Finalize
        for (int i = 0; i < 8; i++)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(Span<ulong> v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 63);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong RotateRight(ulong value, int bits)
    {
        return (value >> bits) | (value << (64 - bits));
    }
}
