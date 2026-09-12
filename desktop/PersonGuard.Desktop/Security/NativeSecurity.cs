using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Interop;

namespace PersonGuard.Desktop.Security;

public static class NativeSecurity
{
    private const uint WdaNone = 0x00000000;
    private const uint WdaExcludeFromCapture = 0x00000011;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint LoadLibrarySearchUserDirs = 0x00000400;
    private const int ProcessExtensionPointDisablePolicy = 6;
    private const int ProcessImageLoadPolicy = 10;
    private const int DwmwaBorderColor = 34;
    private const uint DwmColorNone = 0xFFFFFFFE;

    [StructLayout(LayoutKind.Sequential)]
    private struct MitigationPolicy
    {
        public uint Flags;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(nint hWnd, uint dwAffinity);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(int mitigationPolicy, ref MitigationPolicy buffer, nuint length);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint hWnd, int attribute, ref uint value, uint valueSize);

    public static void HardenProcess()
    {
        try { SetDefaultDllDirectories(LoadLibrarySearchSystem32 | LoadLibrarySearchUserDirs); } catch { }
        try
        {
            var extensionPoints = new MitigationPolicy { Flags = 0x1 };
            SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, ref extensionPoints, (nuint)Marshal.SizeOf<MitigationPolicy>());
        }
        catch { }
        try
        {
            // Block executable images from network/low-integrity locations and prefer System32.
            var imageLoads = new MitigationPolicy { Flags = 0x1 | 0x2 | 0x4 };
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, ref imageLoads, (nuint)Marshal.SizeOf<MitigationPolicy>());
        }
        catch { }
    }

    public static bool SetCaptureProtection(Window window, bool enabled)
    {
        if (Environment.GetEnvironmentVariable("PERSONGUARD_ALLOW_CAPTURE") == "1") enabled = false;
        try
        {
            nint hwnd = new WindowInteropHelper(window).EnsureHandle();
            return SetWindowDisplayAffinity(hwnd, enabled ? WdaExcludeFromCapture : WdaNone);
        }
        catch { return false; }
    }

    public static void RemoveSystemWindowBorder(Window window)
    {
        try
        {
            nint hwnd = new WindowInteropHelper(window).EnsureHandle();
            uint color = DwmColorNone;
            _ = DwmSetWindowAttribute(hwnd, DwmwaBorderColor, ref color, sizeof(uint));
        }
        catch { }
    }

    public static string SignatureStatus()
    {
        try
        {
            string path = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
            if (path.Length == 0) return "Не удалось проверить";
#pragma warning disable SYSLIB0057 // Required to read the Authenticode signer embedded in a PE file.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.Offline, VerificationFlags = X509VerificationFlags.NoFlag } };
            return chain.Build(certificate) ? $"Проверена · {certificate.GetNameInfo(X509NameType.SimpleName, false)}" : "Подпись есть, цепочка не доверена";
        }
        catch { return "DEV‑сборка без подписи"; }
    }
}
