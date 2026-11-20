using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace PersonGuard.Desktop.Security;

public static class SensitiveClipboard
{
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveable = 0x0002;
    private const uint GmemZeroInit = 0x0040;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(nint owner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetClipboardData(uint format, nint memory);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterClipboardFormat(string format);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GlobalAlloc(uint flags, nuint bytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GlobalLock(nint memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(nint memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GlobalFree(nint memory);

    public static bool TrySetText(Window owner, string value, out uint sequence)
    {
        sequence = 0;
        nint hwnd = new WindowInteropHelper(owner).EnsureHandle();
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (!OpenClipboard(hwnd))
            {
                Thread.Sleep(12 * (attempt + 1));
                continue;
            }

            try
            {
                if (!EmptyClipboard()) return false;
                // These Windows-registered formats opt this item out of local history,
                // cloud sync, and clipboard monitor processing.
                // Install all protections before publishing text and fail closed.
                if (!SetZeroDword("CanIncludeInClipboardHistory") ||
                    !SetZeroDword("CanUploadToCloudClipboard") ||
                    !SetZeroDword("ExcludeClipboardContentFromMonitorProcessing") ||
                    !SetUnicodeText(value))
                {
                    EmptyClipboard();
                    return false;
                }
                sequence = GetClipboardSequenceNumber();
                if (sequence == 0) { EmptyClipboard(); return false; }
                return true;
            }
            finally { CloseClipboard(); }
        }
        return false;
    }

    /// <summary>Atomically clear only our clipboard item, without reading its plaintext.</summary>
    public static bool TryClear(Window owner, uint sequence)
    {
        if (sequence == 0) return true;
        if (!OpenClipboard(new WindowInteropHelper(owner).EnsureHandle())) return false;
        try { return GetClipboardSequenceNumber() != sequence || EmptyClipboard(); }
        finally { CloseClipboard(); }
    }

    private static unsafe bool SetUnicodeText(string value)
    {
        nuint byteCount = checked((nuint)((value.Length + 1) * sizeof(char)));
        nint memory = GlobalAlloc(GmemMoveable | GmemZeroInit, byteCount);
        if (memory == 0) return false;
        nint target = GlobalLock(memory);
        if (target == 0) { GlobalFree(memory); return false; }
        try
        {
            fixed (char* source = value)
                Buffer.MemoryCopy(source, (void*)target, (long)byteCount, value.Length * sizeof(char));
        }
        finally { GlobalUnlock(memory); }

        if (SetClipboardData(CfUnicodeText, memory) != 0) return true;
        GlobalFree(memory);
        return false;
    }

    private static bool SetZeroDword(string name)
    {
        uint format = RegisterClipboardFormat(name);
        if (format == 0) return false;
        nint memory = GlobalAlloc(GmemMoveable | GmemZeroInit, sizeof(uint));
        if (memory == 0) return false;
        if (SetClipboardData(format, memory) != 0) return true;
        GlobalFree(memory);
        return false;
    }
}
