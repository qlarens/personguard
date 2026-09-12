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

public sealed class ProtectedBytes : IDisposable
{
    private static readonly byte[] ProcessEntropy = RandomNumberGenerator.GetBytes(32);
    private byte[]? _protected;

    private ProtectedBytes(byte[] protectedValue) => _protected = protectedValue;

    public static ProtectedBytes FromBytes(ReadOnlySpan<byte> value)
    {
        byte[] copy = value.ToArray();
        try { return new ProtectedBytes(ProtectedData.Protect(copy, ProcessEntropy, DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(copy); }
    }

    public byte[] Reveal()
    {
        byte[] protectedValue = _protected ?? throw new ObjectDisposedException(nameof(ProtectedBytes));
        return ProtectedData.Unprotect(protectedValue, ProcessEntropy, DataProtectionScope.CurrentUser);
    }

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
