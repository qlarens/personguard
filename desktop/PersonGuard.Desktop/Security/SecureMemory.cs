using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace PersonGuard.Desktop.Security;

public static class SecureStringUtil
{
    public static unsafe byte[] ToUtf8(SecureString value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        IntPtr pointer = Marshal.SecureStringToGlobalAllocUnicode(value);
        try
        {
            var chars = new ReadOnlySpan<char>((void*)pointer, value.Length);
            byte[] bytes = new byte[Encoding.UTF8.GetByteCount(chars)];
            Encoding.UTF8.GetBytes(chars, bytes);
            return bytes;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        }
    }

    public static bool FixedTimeEquals(SecureString left, SecureString right)
    {
        byte[] a = ToUtf8(left);
        byte[] b = ToUtf8(right);
        try { return CryptographicOperations.FixedTimeEquals(a, b); }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }
}

// CryptProtectMemory(SAME_PROCESS) keeps the key in the kernel: a memory dump read by another
// process cannot be decrypted, unlike DPAPI CurrentUser whose entropy sat in the same memory.
public sealed class ProtectedBytes : IDisposable
{
    private const uint SameProcess = 0;
    private const int BlockSize = 16;
    private byte[]? _protected;
    private readonly int _length;

    private ProtectedBytes(byte[] protectedValue, int length) { _protected = protectedValue; _length = length; }

    public static ProtectedBytes FromBytes(ReadOnlySpan<byte> value)
    {
        // Pinned, so GC compaction cannot leave a plaintext copy behind before encryption.
        byte[] buffer = GC.AllocateArray<byte>((value.Length / BlockSize + 1) * BlockSize, pinned: true);
        value.CopyTo(buffer);
        if (CryptProtectMemory(buffer, (uint)buffer.Length, SameProcess)) return new ProtectedBytes(buffer, value.Length);
        CryptographicOperations.ZeroMemory(buffer);
        throw new CryptographicException(Marshal.GetLastPInvokeError());
    }

    public byte[] Reveal()
    {
        byte[] protectedValue = _protected ?? throw new ObjectDisposedException(nameof(ProtectedBytes));
        byte[] buffer = GC.AllocateArray<byte>(protectedValue.Length, pinned: true);
        protectedValue.CopyTo(buffer, 0);
        try
        {
            if (!CryptUnprotectMemory(buffer, (uint)buffer.Length, SameProcess)) throw new CryptographicException(Marshal.GetLastPInvokeError());
            return buffer.AsSpan(0, _length).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    [DllImport("crypt32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptProtectMemory(byte[] data, uint size, uint flags);

    [DllImport("crypt32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptUnprotectMemory(byte[] data, uint size, uint flags);

    public void Dispose()
    {
        if (_protected is null) return;
        CryptographicOperations.ZeroMemory(_protected);
        _protected = null;
    }
}

public sealed class ProtectedSecret : IDisposable
{
    private ProtectedBytes? _bytes;
    private ProtectedSecret(ProtectedBytes bytes) => _bytes = bytes;

    public static ProtectedSecret FromSecureString(SecureString value)
    {
        byte[] bytes = SecureStringUtil.ToUtf8(value);
        try { return new ProtectedSecret(ProtectedBytes.FromBytes(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static ProtectedSecret FromString(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        try { return new ProtectedSecret(ProtectedBytes.FromBytes(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public byte[] RevealUtf8() => (_bytes ?? throw new ObjectDisposedException(nameof(ProtectedSecret))).Reveal();

    public string RevealForDisplay()
    {
        byte[] bytes = RevealUtf8();
        try { return Encoding.UTF8.GetString(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void Dispose()
    {
        _bytes?.Dispose();
        _bytes = null;
    }
}
