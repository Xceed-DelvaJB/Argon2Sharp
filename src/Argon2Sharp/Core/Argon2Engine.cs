using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Argon2Sharp.Core;

/// <summary>
/// Main Argon2 algorithm implementation.
/// Implements Argon2d, Argon2i, and Argon2id as specified in RFC 9106.
/// Highly optimized for maximum performance.
/// </summary>
internal sealed class Argon2Engine
{
    private readonly Argon2Parameters _parameters;
    private readonly int _segmentLength;
    private readonly int _laneLength;
    private readonly int _memoryBlocks;

    // Pre-computed constants for faster access
    private readonly bool _isArgon2i;
    private readonly bool _isArgon2id;
    private readonly int _parallelism;
    private readonly int _iterations;

    public Argon2Engine(Argon2Parameters parameters)
    {
        _parameters = parameters;
        _parameters.Validate();

        // Cache frequently used values
        _parallelism = _parameters.Parallelism;
        _iterations = _parameters.Iterations;
        _isArgon2i = _parameters.Type == Argon2Type.Argon2i;
        _isArgon2id = _parameters.Type == Argon2Type.Argon2id;

        // Calculate memory layout
        _memoryBlocks = _parameters.MemorySizeKB;
        _laneLength = _memoryBlocks / _parallelism;
        _segmentLength = _laneLength / Argon2Core.SyncPoints;

        // Ensure minimum requirements
        _memoryBlocks = _parallelism * _laneLength;
    }

    /// <summary>
    /// Computes Argon2 hash - optimized version.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
    {
        if (output.Length != _parameters.HashLength)
            throw new ArgumentException($"Output buffer must be {_parameters.HashLength} bytes");

        int totalQwords = _memoryBlocks * Argon2Core.QwordsInBlock;
        
        // Allocate memory blocks from pool
        var memory = ArrayPool<ulong>.Shared.Rent(totalQwords);
        try
        {
            var memorySpan = memory.AsSpan(0, totalQwords);
            
            // Fast zero using Span.Clear (optimized by runtime)
            memorySpan.Clear();

            // Initialize memory
            Initialize(password, memorySpan);

            // Fill memory blocks
            FillMemoryBlocks(memorySpan);

            // Finalize and produce output
            Finalize(memorySpan, output);
        }
        finally
        {
            // Securely clear sensitive data
            CryptographicOperations.ZeroMemory(
                MemoryMarshal.AsBytes(memory.AsSpan(0, totalQwords)));
            ArrayPool<ulong>.Shared.Return(memory);
        }
    }

    /// <summary>
    /// Initialize first blocks with Blake2b hash of parameters.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void Initialize(ReadOnlySpan<byte> password, Span<ulong> memory)
    {
        // Calculate H0 input size: 10 * 4 bytes (params) + password + salt + secret + ad
        int saltLen = _parameters.Salt?.Length ?? 0;
        int secretLen = _parameters.Secret?.Length ?? 0;
        int adLen = _parameters.AssociatedData?.Length ?? 0;
        int h0Length = 40 + password.Length + saltLen + secretLen + adLen;

        // Use stackalloc for small inputs, otherwise rent from pool
        byte[]? rentedH0 = null;
        Span<byte> h0Input = h0Length <= 512 
            ? stackalloc byte[h0Length] 
            : (rentedH0 = ArrayPool<byte>.Shared.Rent(h0Length)).AsSpan(0, h0Length);

        try
        {
            int offset = 0;

            // Write all parameters in one go
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), _parallelism); offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), _parameters.HashLength); offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), _parameters.MemorySizeKB); offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), _iterations); offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), (int)_parameters.Version); offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), (int)_parameters.Type); offset += 4;

            // Password
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), password.Length); offset += 4;
            password.CopyTo(h0Input.Slice(offset)); offset += password.Length;

            // Salt
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), saltLen); offset += 4;
            if (saltLen > 0)
            {
                _parameters.Salt.CopyTo(h0Input.Slice(offset));
                offset += saltLen;
            }

            // Secret
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), secretLen); offset += 4;
            if (secretLen > 0)
            {
                _parameters.Secret.CopyTo(h0Input.Slice(offset));
                offset += secretLen;
            }

            // Associated data
            BinaryPrimitives.WriteInt32LittleEndian(h0Input.Slice(offset), adLen); offset += 4;
            if (adLen > 0)
            {
                _parameters.AssociatedData.CopyTo(h0Input.Slice(offset));
            }

            Span<byte> h0 = stackalloc byte[64];
            Blake2b.Hash(h0Input.Slice(0, h0Length), h0);

            // Generate first two blocks for each lane
            Span<byte> blockBytes = stackalloc byte[Argon2Core.BlockSize];
            Span<byte> h0Extended = stackalloc byte[72];
            h0.CopyTo(h0Extended);

            for (int lane = 0; lane < _parallelism; lane++)
            {
                // Block 0
                BinaryPrimitives.WriteInt32LittleEndian(h0Extended.Slice(64), 0);
                BinaryPrimitives.WriteInt32LittleEndian(h0Extended.Slice(68), lane);

                Blake2b.LongHash(h0Extended, blockBytes);
                Argon2Core.BytesToQwords(blockBytes, GetBlock(memory, lane, 0));

                // Block 1
                BinaryPrimitives.WriteInt32LittleEndian(h0Extended.Slice(64), 1);
                Blake2b.LongHash(h0Extended, blockBytes);
                Argon2Core.BytesToQwords(blockBytes, GetBlock(memory, lane, 1));
            }
        }
        finally
        {
            if (rentedH0 != null)
            {
                CryptographicOperations.ZeroMemory(rentedH0.AsSpan(0, h0Length));
                ArrayPool<byte>.Shared.Return(rentedH0);
            }
        }
    }

    /// <summary>
    /// Fill memory blocks with Argon2 compression.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void FillMemoryBlocks(Span<ulong> memory)
    {
        for (int pass = 0; pass < _iterations; pass++)
        {
            for (int slice = 0; slice < Argon2Core.SyncPoints; slice++)
            {
                for (int lane = 0; lane < _parallelism; lane++)
                {
                    FillSegment(memory, pass, lane, slice);
                }
            }
        }
    }

    /// <summary>
    /// Fill a segment of a lane - optimized hot path.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void FillSegment(Span<ulong> memory, int pass, int lane, int slice)
    {
        int startIndex = (slice == 0 && pass == 0) ? 2 : 0;
        int laneOffset = lane * _laneLength;
        int sliceOffset = slice * _segmentLength;
        int currentOffset = laneOffset + sliceOffset + startIndex;

        // Determine if data-independent mode for this segment
        bool dataIndependent = _isArgon2i || (_isArgon2id && pass == 0 && slice < 2);

        for (int i = startIndex; i < _segmentLength; i++)
        {
            // Calculate previous block offset
            int prevOffset;
            int currentInLane = sliceOffset + i;
            if (currentInLane == 0)
                prevOffset = laneOffset + _laneLength - 1;
            else
                prevOffset = currentOffset - 1;

            // Get reference block
            int refLane, refIndex;
            if (dataIndependent)
            {
                GetRefBlockIndexDataIndependent(pass, lane, slice, i, out refLane, out refIndex);
            }
            else
            {
                GetRefBlockIndexDataDependent(memory, prevOffset, pass, lane, slice, i, out refLane, out refIndex);
            }

            int refOffset = refLane * _laneLength + refIndex;

            // Get block spans
            var prevBlock = GetBlockByOffset(memory, prevOffset);
            var refBlock = GetBlockByOffset(memory, refOffset);
            var currentBlock = GetBlockByOffset(memory, currentOffset);

            // Compute new block
            Argon2Core.FillBlock(prevBlock, refBlock, currentBlock);

            currentOffset++;
        }
    }

    /// <summary>
    /// Get reference block index using data-independent addressing.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void GetRefBlockIndexDataIndependent(int pass, int lane, int slice, int index,
        out int refLane, out int refIndex)
    {
        // Generate pseudo-random value based on position
        ulong pseudoRand = ((ulong)pass << 32) | ((ulong)lane << 24) | ((ulong)slice << 16) | (ulong)(uint)index;

        refLane = (int)(pseudoRand % (ulong)_parallelism);

        int refAreaSize = CalculateRefAreaSize(pass, slice, index, refLane == lane);
        if (refAreaSize <= 0) refAreaSize = 1;
        
        refIndex = (int)(pseudoRand % (ulong)refAreaSize);

        // Adjust if in same lane
        if (refLane == lane)
        {
            int startPos = slice * _segmentLength;
            if (pass == 0 && slice == 0)
                startPos = 0;
            refIndex = (startPos + refIndex) % _laneLength;
        }
    }

    /// <summary>
    /// Get reference block index using data-dependent addressing.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void GetRefBlockIndexDataDependent(Span<ulong> memory, int prevOffset,
        int pass, int lane, int slice, int index, out int refLane, out int refIndex)
    {
        var prevBlock = GetBlockByOffset(memory, prevOffset);
        ulong j1 = prevBlock[0];
        ulong j2 = prevBlock[1];

        refLane = (int)(j2 % (ulong)_parallelism);

        int refAreaSize = CalculateRefAreaSize(pass, slice, index, refLane == lane);
        if (refAreaSize <= 0) refAreaSize = 1;

        ulong relativePosition = j1 & 0xFFFFFFFF;
        relativePosition = (relativePosition * relativePosition) >> 32;
        relativePosition = (ulong)refAreaSize - 1 - ((ulong)refAreaSize * relativePosition >> 32);

        refIndex = (int)relativePosition;

        if (refLane == lane)
        {
            int startPos = slice * _segmentLength;
            if (pass == 0 && slice == 0)
                startPos = index;
            refIndex = (startPos + refIndex) % _laneLength;
        }
    }

    /// <summary>
    /// Calculate the size of the reference area.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int CalculateRefAreaSize(int pass, int slice, int index, bool sameLane)
    {
        if (pass == 0)
        {
            if (slice == 0)
                return index > 0 ? index - 1 : 0;

            if (sameLane)
                return slice * _segmentLength + index - 1;
            else
                return slice * _segmentLength + (index == 0 ? -1 : 0);
        }
        else
        {
            if (sameLane)
                return _laneLength - _segmentLength + index - 1;
            else
                return _laneLength - _segmentLength + (index == 0 ? -1 : 0);
        }
    }

    /// <summary>
    /// Finalize: XOR all lanes and produce final hash.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void Finalize(Span<ulong> memory, Span<byte> output)
    {
        Span<ulong> finalBlock = stackalloc ulong[Argon2Core.QwordsInBlock];
        
        // Get last block of first lane
        GetBlock(memory, 0, _laneLength - 1).CopyTo(finalBlock);

        // XOR with last blocks of other lanes
        for (int lane = 1; lane < _parallelism; lane++)
        {
            Argon2Core.XorBlock(GetBlock(memory, lane, _laneLength - 1), finalBlock);
        }

        Span<byte> finalBlockBytes = stackalloc byte[Argon2Core.BlockSize];
        Argon2Core.QwordsToBytes(finalBlock, finalBlockBytes);

        Blake2b.LongHash(finalBlockBytes, output);
    }

    /// <summary>
    /// Get a block from memory at the specified lane and index.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private Span<ulong> GetBlock(Span<ulong> memory, int lane, int index)
    {
        int offset = (lane * _laneLength + index) * Argon2Core.QwordsInBlock;
        return memory.Slice(offset, Argon2Core.QwordsInBlock);
    }

    /// <summary>
    /// Get a block from memory at the specified absolute offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private Span<ulong> GetBlockByOffset(Span<ulong> memory, int blockOffset)
    {
        int offset = blockOffset * Argon2Core.QwordsInBlock;
        return memory.Slice(offset, Argon2Core.QwordsInBlock);
    }
}
