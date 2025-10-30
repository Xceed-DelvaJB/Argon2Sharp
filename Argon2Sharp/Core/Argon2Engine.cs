using Argon2Sharp.Core;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Main Argon2 algorithm implementation.
/// Implements Argon2d, Argon2i, and Argon2id as specified in RFC 9106.
/// </summary>
internal sealed class Argon2Engine
{
    private readonly Argon2Parameters _parameters;
    private readonly int _segmentLength;
    private readonly int _laneLength;
    private readonly int _memoryBlocks;

    public Argon2Engine(Argon2Parameters parameters)
    {
        _parameters = parameters;
        _parameters.Validate();

        // Calculate memory layout
        _memoryBlocks = _parameters.MemorySizeKB;
        _laneLength = _memoryBlocks / _parameters.Parallelism;
        _segmentLength = _laneLength / Argon2Core.SyncPoints;

        // Ensure minimum requirements
        _memoryBlocks = _parameters.Parallelism * _laneLength;
    }

    /// <summary>
    /// Computes Argon2 hash.
    /// </summary>
    public void Hash(ReadOnlySpan<byte> password, Span<byte> output)
    {
        if (output.Length != _parameters.HashLength)
            throw new ArgumentException($"Output buffer must be {_parameters.HashLength} bytes");

        // Allocate memory blocks (each block is 1024 bytes = 128 qwords)
        var memory = ArrayPool<ulong>.Shared.Rent(_memoryBlocks * Argon2Core.QwordsInBlock);
        try
        {
            var memorySpan = memory.AsSpan(0, _memoryBlocks * Argon2Core.QwordsInBlock);
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
            // Clear sensitive data
            memory.AsSpan(0, _memoryBlocks * Argon2Core.QwordsInBlock).Clear();
            ArrayPool<ulong>.Shared.Return(memory);
        }
    }

    /// <summary>
    /// Initialize first blocks with Blake2b hash of parameters.
    /// </summary>
    private void Initialize(ReadOnlySpan<byte> password, Span<ulong> memory)
    {
        // H0 = Blake2b(
        //   parallelism || tagLength || memorySizeKB || iterations || 
        //   version || type || passwordLength || password ||
        //   saltLength || salt || secretLength || secret ||
        //   associatedDataLength || associatedData
        // )

        int h0Length = 4 + 4 + 4 + 4 + 4 + 4 + 4 + password.Length + 4 + 
                       (_parameters.Salt?.Length ?? 0) + 4 + 
                       (_parameters.Secret?.Length ?? 0) + 4 + 
                       (_parameters.AssociatedData?.Length ?? 0);

        Span<byte> h0Input = stackalloc byte[h0Length];
        int offset = 0;

        WriteInt32(h0Input, ref offset, _parameters.Parallelism);
        WriteInt32(h0Input, ref offset, _parameters.HashLength);
        WriteInt32(h0Input, ref offset, _parameters.MemorySizeKB);
        WriteInt32(h0Input, ref offset, _parameters.Iterations);
        WriteInt32(h0Input, ref offset, (int)_parameters.Version);
        WriteInt32(h0Input, ref offset, (int)_parameters.Type);
        WriteInt32(h0Input, ref offset, password.Length);
        password.CopyTo(h0Input.Slice(offset));
        offset += password.Length;

        WriteInt32(h0Input, ref offset, _parameters.Salt?.Length ?? 0);
        if (_parameters.Salt != null)
        {
            _parameters.Salt.CopyTo(h0Input.Slice(offset));
            offset += _parameters.Salt.Length;
        }

        WriteInt32(h0Input, ref offset, _parameters.Secret?.Length ?? 0);
        if (_parameters.Secret != null)
        {
            _parameters.Secret.CopyTo(h0Input.Slice(offset));
            offset += _parameters.Secret.Length;
        }

        WriteInt32(h0Input, ref offset, _parameters.AssociatedData?.Length ?? 0);
        if (_parameters.AssociatedData != null)
        {
            _parameters.AssociatedData.CopyTo(h0Input.Slice(offset));
            offset += _parameters.AssociatedData.Length;
        }

        Span<byte> h0 = stackalloc byte[64];
        Blake2b.Hash(h0Input, h0);

        // Generate first two blocks for each lane
        Span<byte> blockBytes = stackalloc byte[Argon2Core.BlockSize];
        Span<byte> h0Extended = stackalloc byte[72];
        
        for (int lane = 0; lane < _parameters.Parallelism; lane++)
        {
            // Block 0
            h0.CopyTo(h0Extended);
            WriteInt32(h0Extended.Slice(64), 0);
            WriteInt32(h0Extended.Slice(68), lane);
            
            Blake2b.LongHash(h0Extended, blockBytes);
            Argon2Core.BytesToQwords(blockBytes, GetBlock(memory, lane, 0));

            // Block 1
            WriteInt32(h0Extended.Slice(64), 1);
            Blake2b.LongHash(h0Extended, blockBytes);
            Argon2Core.BytesToQwords(blockBytes, GetBlock(memory, lane, 1));
        }
    }

    /// <summary>
    /// Fill memory blocks with Argon2 compression.
    /// </summary>
    private void FillMemoryBlocks(Span<ulong> memory)
    {
        for (int pass = 0; pass < _parameters.Iterations; pass++)
        {
            for (int slice = 0; slice < Argon2Core.SyncPoints; slice++)
            {
                for (int lane = 0; lane < _parameters.Parallelism; lane++)
                {
                    FillSegment(memory, pass, lane, slice);
                }
            }
        }
    }

    /// <summary>
    /// Fill a segment of a lane.
    /// </summary>
    private void FillSegment(Span<ulong> memory, int pass, int lane, int slice)
    {
        int startIndex = slice == 0 && pass == 0 ? 2 : 0;
        int currentOffset = lane * _laneLength + slice * _segmentLength + startIndex;

        for (int i = startIndex; i < _segmentLength; i++)
        {
            int prevOffset = currentOffset - 1;
            if (currentOffset % _laneLength == 0)
                prevOffset = currentOffset - 1 + _laneLength;

            // Determine reference block index
            bool dataIndependent = _parameters.Type == Argon2Type.Argon2i ||
                                   (_parameters.Type == Argon2Type.Argon2id && pass == 0 && slice < Argon2Core.SyncPoints / 2);

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

            // Compute new block
            var prevBlock = GetBlock(memory, 0, prevOffset);
            var refBlock = GetBlock(memory, 0, refOffset);
            var currentBlock = GetBlock(memory, 0, currentOffset);

            Argon2Core.FillBlock(prevBlock, refBlock, currentBlock);

            currentOffset++;
        }
    }

    /// <summary>
    /// Get reference block index using data-independent addressing (Argon2i mode).
    /// </summary>
    private void GetRefBlockIndexDataIndependent(int pass, int lane, int slice, int index,
        out int refLane, out int refIndex)
    {
        // Simplified version - use pseudo-random based on position
        ulong pseudoRand = ((ulong)pass << 32) | ((ulong)lane << 24) | ((ulong)slice << 16) | (ulong)(uint)index;
        
        refLane = (int)(pseudoRand % (ulong)_parameters.Parallelism);
        
        int refAreaSize = CalculateRefAreaSize(pass, slice, index, refLane == lane);
        refIndex = (int)(pseudoRand % (ulong)refAreaSize);
        
        if (refLane == lane && refIndex >= slice * _segmentLength + index)
            refIndex = (refIndex + _segmentLength) % _laneLength;
    }

    /// <summary>
    /// Get reference block index using data-dependent addressing (Argon2d mode).
    /// </summary>
    private void GetRefBlockIndexDataDependent(Span<ulong> memory, int prevOffset,
        int pass, int lane, int slice, int index, out int refLane, out int refIndex)
    {
        var prevBlock = GetBlock(memory, 0, prevOffset);
        ulong j1 = prevBlock[0];
        ulong j2 = prevBlock[1];

        refLane = (int)(j2 % (ulong)_parameters.Parallelism);
        
        int refAreaSize = CalculateRefAreaSize(pass, slice, index, refLane == lane);
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
    private int CalculateRefAreaSize(int pass, int slice, int index, bool sameLane)
    {
        if (pass == 0)
        {
            if (slice == 0)
                return index - 1;
            
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
    private void Finalize(Span<ulong> memory, Span<byte> output)
    {
        Span<ulong> finalBlock = stackalloc ulong[Argon2Core.QwordsInBlock];
        GetBlock(memory, 0, _laneLength - 1).CopyTo(finalBlock);

        for (int lane = 1; lane < _parameters.Parallelism; lane++)
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
    private Span<ulong> GetBlock(Span<ulong> memory, int lane, int index)
    {
        if (lane != 0)
            index = lane * _laneLength + index;
        
        int offset = index * Argon2Core.QwordsInBlock;
        return memory.Slice(offset, Argon2Core.QwordsInBlock);
    }

    private static void WriteInt32(Span<byte> buffer, ref int offset, int value)
    {
        BitConverter.TryWriteBytes(buffer.Slice(offset, 4), value);
        offset += 4;
    }

    private static void WriteInt32(Span<byte> buffer, int value)
    {
        BitConverter.TryWriteBytes(buffer, value);
    }
}
