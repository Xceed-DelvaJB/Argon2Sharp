using System;
using System.Runtime.CompilerServices;

namespace DotNet5Compatibility
{
    internal static class ArgumentNullException
    {
        public static void ThrowIfNull(object? argument, string? paramName = default)
        {
            if (argument == null)
            {
                throw new System.ArgumentNullException(paramName);
            }
        }
    }

    internal static class ULong
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong RotateRight(ulong value, int count)
        {
            ulong result = (value >> count) | (value << (-count));

            return result;
        }
    }
}
