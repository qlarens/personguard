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

    public static bool SetRoundedCorners(Window window, bool rounded)
    {
        try
        {
            nint hwnd = new WindowInteropHelper(window).EnsureHandle();
            uint preference = rounded ? 2u : 1u;
            return DwmSetWindowAttribute(hwnd, 33, ref preference, sizeof(uint)) == 0;
        }
        catch { return false; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustFileInfo
    {
        public uint Size;
        public nint Path;
        public nint File;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size;
        public nint PolicyCallback;
        public nint SipClient;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint FileInfo;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(nint window, ref Guid action, ref TrustData data);

    public static bool HasTrustedSignature(string path)
    {
        nint pathMemory = Marshal.StringToCoTaskMemUni(path);
        nint fileMemory = Marshal.AllocHGlobal(Marshal.SizeOf<TrustFileInfo>());
        var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
        var data = new TrustData
        {
            Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2, UnionChoice = 1,
            FileInfo = fileMemory, StateAction = 1,
            // Offline trust validation. Never initiate certificate network requests.
            ProviderFlags = 0x1000,
        };
        try
        {
            Marshal.StructureToPtr(new TrustFileInfo { Size = (uint)Marshal.SizeOf<TrustFileInfo>(), Path = pathMemory }, fileMemory, false);
            // Verify the actual PE digest and signer, rather than just the certificate chain.
            return WinVerifyTrust(new nint(-1), ref action, ref data) == 0;
        }
        catch { return false; }
        finally
        {
            data.StateAction = 2;
            try { WinVerifyTrust(new nint(-1), ref action, ref data); } catch { }
            Marshal.FreeHGlobal(fileMemory);
            Marshal.FreeCoTaskMem(pathMemory);
        }
    }

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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out nint descriptor, nint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(nint descriptor, out bool present, out nint dacl, out bool defaulted);

    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(nint handle, int objectType, uint securityInfo, nint owner, nint group, nint dacl, nint sacl);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint memory);

    /// <summary>
    /// Same-user processes may only query, wait for and end PersonGuard: no memory reads, injection or
    /// handle duplication. The OWNER RIGHTS ACE removes the owner's implicit WRITE_DAC, so loosening
    /// this DACL again needs SeDebugPrivilege (administrator).
    /// </summary>
    public static bool RestrictProcessAccess()
    {
        const string limited = "0x101001"; // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
        string user = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;{limited};;;{user})(A;;{limited};;;OW)(A;;0x1FFFFF;;;SY)", 1, out nint descriptor, 0))
            return false;
        try
        {
            // SE_KERNEL_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            return GetSecurityDescriptorDacl(descriptor, out bool present, out nint dacl, out _) && present &&
                SetSecurityInfo(GetCurrentProcess(), 6, 0x80000004, 0, 0, dacl, 0) == 0;
        }
        finally { LocalFree(descriptor); }
    }

    public static void HardenProcess()
    {
        try { RestrictProcessAccess(); } catch { }
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
#if DEBUG
        // Screenshot tooling only: in release a user-scope variable would be a silent kill switch for malware.
        if (Environment.GetEnvironmentVariable("PERSONGUARD_ALLOW_CAPTURE") == "1") enabled = false;
#endif
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

    /// <summary>A folder writable without elevation lets same-user malware swap the exe and capture the master password.</summary>
    public static bool InstallFolderWritable()
    {
        try
        {
            string directory = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            using var probe = new FileStream(Path.Combine(directory, $".pg-write-check-{Guid.NewGuid():N}"),
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
            return true;
        }
        catch { return false; }
    }

    public static string SignatureStatus()
    {
        try
        {
            string path = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
            if (path.Length == 0) return "Не удалось проверить";
            if (!HasTrustedSignature(path)) return "Сборка не имеет доверенной Authenticode-подписи (офлайн)";
#pragma warning disable SYSLIB0057 // Required to read the Authenticode signer embedded in a PE file.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return $"Authenticode проверена офлайн · {certificate.GetNameInfo(X509NameType.SimpleName, false)}";
        }
        catch { return "DEV‑сборка без подписи"; }
    }
}
