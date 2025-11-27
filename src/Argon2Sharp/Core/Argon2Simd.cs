using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace Argon2Sharp.Core;

/// <summary>
/// Hardware-accelerated implementations of Argon2 core operations using SIMD intrinsics.
/// </summary>
/// <remarks>
/// <para>This class provides optimized implementations for different CPU architectures:</para>
/// <list type="bullet">
/// <item><b>AVX-512</b>: Intel/AMD processors with AVX-512F support</item>
/// <item><b>AVX2</b>: Intel/AMD processors with AVX2 support</item>
/// <item><b>ARM NEON</b>: ARM64 processors (Apple Silicon, ARM servers)</item>
/// <item><b>Scalar</b>: Fallback for other architectures</item>
/// </list>
/// </remarks>
internal static class Argon2Simd
{
    /// <summary>
    /// Gets the best available SIMD implementation.
    /// </summary>
    public static SimdLevel BestAvailableSimd
    {
        get
        {
            if (Avx512F.IsSupported)
            {
                return SimdLevel.Avx512;
            }
            
            if (Avx2.IsSupported)
            {
                return SimdLevel.Avx2;
            }
            
            if (AdvSimd.Arm64.IsSupported)
            {
                return SimdLevel.ArmNeon;
            }
            
            return SimdLevel.Scalar;
        }
    }

    /// <summary>
    /// XOR two blocks together, using the best available SIMD.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void XorBlocks(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        if (Avx512F.IsSupported)
        {
            XorBlocksAvx512(source, destination);
        }
        else if (Avx2.IsSupported)
        {
            XorBlocksAvx2(source, destination);
        }
        else if (AdvSimd.Arm64.IsSupported)
        {
            XorBlocksNeon(source, destination);
        }
        else
        {
            XorBlocksScalar(source, destination);
        }
    }

    /// <summary>
    /// Fill block operation using best available SIMD.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void FillBlockSimd(
        ReadOnlySpan<ulong> prevBlock,
        ReadOnlySpan<ulong> refBlock,
        Span<ulong> nextBlock)
    {
        if (Avx512F.IsSupported)
        {
            FillBlockAvx512(prevBlock, refBlock, nextBlock);
        }
        else if (Avx2.IsSupported)
        {
            FillBlockAvx2(prevBlock, refBlock, nextBlock);
        }
        else if (AdvSimd.Arm64.IsSupported)
        {
            FillBlockNeon(prevBlock, refBlock, nextBlock);
        }
        else
        {
            FillBlockScalar(prevBlock, refBlock, nextBlock);
        }
    }

    #region AVX-512 Implementation

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void XorBlocksAvx512(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 8; // 512 bits = 8 x 64-bit
        
        fixed (ulong* srcPtr = source)
        fixed (ulong* dstPtr = destination)
        {
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var srcVec = Avx512F.LoadVector512(srcPtr + i);
                var dstVec = Avx512F.LoadVector512(dstPtr + i);
                var result = Avx512F.Xor(srcVec, dstVec);
                Avx512F.Store(dstPtr + i, result);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void FillBlockAvx512(
        ReadOnlySpan<ulong> prevBlock,
        ReadOnlySpan<ulong> refBlock,
        Span<ulong> nextBlock)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 8;
        
        // Temporary storage for R and Z blocks
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];
        
        fixed (ulong* prevPtr = prevBlock)
        fixed (ulong* refPtr = refBlock)
        fixed (ulong* rPtr = r)
        fixed (ulong* zPtr = z)
        fixed (ulong* nextPtr = nextBlock)
        {
            // R = prev XOR ref (using AVX-512)
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = Avx512F.LoadVector512(prevPtr + i);
                var refVec = Avx512F.LoadVector512(refPtr + i);
                var xorResult = Avx512F.Xor(prevVec, refVec);
                Avx512F.Store(rPtr + i, xorResult);
            }
            
            // Copy R to Z
            r.CopyTo(z);
            
            // Apply permutation P to Z
            Argon2Core.PermutationP(z);
            
            // nextBlock = prev XOR ref XOR P(R) (using AVX-512)
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = Avx512F.LoadVector512(prevPtr + i);
                var refVec = Avx512F.LoadVector512(refPtr + i);
                var zVec = Avx512F.LoadVector512(zPtr + i);
                var result = Avx512F.Xor(Avx512F.Xor(prevVec, refVec), zVec);
                Avx512F.Store(nextPtr + i, result);
            }
        }
    }

    #endregion

    #region AVX2 Implementation

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void XorBlocksAvx2(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 4; // 256 bits = 4 x 64-bit
        
        fixed (ulong* srcPtr = source)
        fixed (ulong* dstPtr = destination)
        {
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var srcVec = Avx.LoadVector256(srcPtr + i);
                var dstVec = Avx.LoadVector256(dstPtr + i);
                var result = Avx2.Xor(srcVec, dstVec);
                Avx.Store(dstPtr + i, result);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void FillBlockAvx2(
        ReadOnlySpan<ulong> prevBlock,
        ReadOnlySpan<ulong> refBlock,
        Span<ulong> nextBlock)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 4;
        
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];
        
        fixed (ulong* prevPtr = prevBlock)
        fixed (ulong* refPtr = refBlock)
        fixed (ulong* rPtr = r)
        fixed (ulong* zPtr = z)
        fixed (ulong* nextPtr = nextBlock)
        {
            // R = prev XOR ref
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = Avx.LoadVector256(prevPtr + i);
                var refVec = Avx.LoadVector256(refPtr + i);
                var xorResult = Avx2.Xor(prevVec, refVec);
                Avx.Store(rPtr + i, xorResult);
            }
            
            r.CopyTo(z);
            Argon2Core.PermutationP(z);
            
            // nextBlock = prev XOR ref XOR P(R)
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = Avx.LoadVector256(prevPtr + i);
                var refVec = Avx.LoadVector256(refPtr + i);
                var zVec = Avx.LoadVector256(zPtr + i);
                var result = Avx2.Xor(Avx2.Xor(prevVec, refVec), zVec);
                Avx.Store(nextPtr + i, result);
            }
        }
    }

    #endregion

    #region ARM NEON Implementation

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void XorBlocksNeon(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 2; // 128 bits = 2 x 64-bit
        
        fixed (ulong* srcPtr = source)
        fixed (ulong* dstPtr = destination)
        {
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var srcVec = AdvSimd.LoadVector128(srcPtr + i);
                var dstVec = AdvSimd.LoadVector128(dstPtr + i);
                var result = AdvSimd.Xor(srcVec, dstVec);
                AdvSimd.Store(dstPtr + i, result);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static unsafe void FillBlockNeon(
        ReadOnlySpan<ulong> prevBlock,
        ReadOnlySpan<ulong> refBlock,
        Span<ulong> nextBlock)
    {
        const int QwordsInBlock = 128;
        const int VectorSize = 2;
        
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];
        
        fixed (ulong* prevPtr = prevBlock)
        fixed (ulong* refPtr = refBlock)
        fixed (ulong* rPtr = r)
        fixed (ulong* zPtr = z)
        fixed (ulong* nextPtr = nextBlock)
        {
            // R = prev XOR ref
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = AdvSimd.LoadVector128(prevPtr + i);
                var refVec = AdvSimd.LoadVector128(refPtr + i);
                var xorResult = AdvSimd.Xor(prevVec, refVec);
                AdvSimd.Store(rPtr + i, xorResult);
            }
            
            r.CopyTo(z);
            Argon2Core.PermutationP(z);
            
            // nextBlock = prev XOR ref XOR P(R)
            for (int i = 0; i < QwordsInBlock; i += VectorSize)
            {
                var prevVec = AdvSimd.LoadVector128(prevPtr + i);
                var refVec = AdvSimd.LoadVector128(refPtr + i);
                var zVec = AdvSimd.LoadVector128(zPtr + i);
                var result = AdvSimd.Xor(AdvSimd.Xor(prevVec, refVec), zVec);
                AdvSimd.Store(nextPtr + i, result);
            }
        }
    }

    #endregion

    #region Scalar Fallback

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void XorBlocksScalar(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        for (int i = 0; i < source.Length; i++)
        {
            destination[i] ^= source[i];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void FillBlockScalar(
        ReadOnlySpan<ulong> prevBlock,
        ReadOnlySpan<ulong> refBlock,
        Span<ulong> nextBlock)
    {
        const int QwordsInBlock = 128;
        
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];
        
        // R = prev XOR ref
        for (int i = 0; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }
        
        r.CopyTo(z);
        Argon2Core.PermutationP(z);
        
        // nextBlock = prev XOR ref XOR P(R)
        for (int i = 0; i < QwordsInBlock; i++)
        {
            nextBlock[i] = prevBlock[i] ^ refBlock[i] ^ z[i];
        }
    }

    #endregion
}

/// <summary>
/// Available SIMD instruction set levels.
/// </summary>
public enum SimdLevel
{
    /// <summary>No SIMD, scalar operations only.</summary>
    Scalar = 0,
    
    /// <summary>ARM NEON (128-bit vectors).</summary>
    ArmNeon = 1,
    
    /// <summary>x86 AVX2 (256-bit vectors).</summary>
    Avx2 = 2,
    
    /// <summary>x86 AVX-512 (512-bit vectors).</summary>
    Avx512 = 3
}
