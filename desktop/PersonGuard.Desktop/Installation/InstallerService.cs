using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace PersonGuard.Desktop.Installation;

public enum UninstallOutcome
{
    Success,
    Canceled,
    Failure
}

public sealed record InstallResult(string InstalledExecutable, bool WasUpdate);
public sealed record UninstallResult(UninstallOutcome Outcome, string Message);

public static class InstallerService
{
    public const string ProductName = "PersonGuard";
    public const string Version = "2.0.0";
    public const string Publisher = "Clarence Everhart (qlarens)";
    private const string AppMutexName = "Local\\PersonGuard.Desktop.Singleton";
    private const string UninstallRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\PersonGuard";

    public static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs",
        ProductName);

    public static string InstalledExecutable => Path.Combine(InstallDirectory, "PersonGuard.exe");
    public static bool IsInstalled => File.Exists(InstalledExecutable);

    public static bool IsSetupRequest(IReadOnlyList<string> args)
    {
        if (args.Any(arg => string.Equals(arg, "--install", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (IsRunningFromInstallDirectory())
            return false;

#if PERSONGUARD_INSTALLER_BUILD
        return true;
#else
        string fileName = Path.GetFileNameWithoutExtension(CurrentExecutable());
        return fileName.Contains("setup", StringComparison.OrdinalIgnoreCase);
#endif
    }

    public static bool IsUninstallRequest(IReadOnlyList<string> args, out bool quiet)
    {
        quiet = args.Any(arg => string.Equals(arg, "--quiet", StringComparison.OrdinalIgnoreCase));
        return args.Any(arg => string.Equals(arg, "--uninstall", StringComparison.OrdinalIgnoreCase));
    }

    public static InstallResult Install(bool createDesktopShortcut)
    {
        if (IsApplicationRunning())
            throw new InvalidOperationException("Закройте запущенный PersonGuard и повторите установку.");

        string source = CurrentExecutable();
        string installDirectory = Path.GetFullPath(InstallDirectory);
        string destination = Path.GetFullPath(InstalledExecutable);
        bool wasUpdate = File.Exists(destination);
        Directory.CreateDirectory(installDirectory);

        string stagedExecutable = destination + ".installing";
        try
        {
            File.Copy(source, stagedExecutable, overwrite: true);
            File.Move(stagedExecutable, destination, overwrite: true);
            File.WriteAllText(Path.Combine(installDirectory, "LICENSE.txt"), LicenseInfo.Text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            CreateShortcut(StartMenuShortcut, destination);
            if (createDesktopShortcut)
                CreateShortcut(DesktopShortcut, destination);
            else
                DeleteFileIfPresent(DesktopShortcut);

            RegisterUninstaller(destination);
            return new InstallResult(destination, wasUpdate);
        }
        catch
        {
            DeleteFileIfPresent(stagedExecutable);
            throw;
        }
    }

    public static UninstallResult Uninstall(bool quiet)
    {
        if (IsApplicationRunning())
            return new UninstallResult(UninstallOutcome.Failure, "Закройте запущенный PersonGuard и повторите удаление.");

        if (!quiet)
        {
            System.Windows.MessageBoxResult confirmation = System.Windows.MessageBox.Show(
                "Удалить PersonGuard с этого компьютера?\n\nЗашифрованные сейфы .pgd и личные настройки останутся на месте.",
                "Удаление PersonGuard",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Question,
                System.Windows.MessageBoxResult.No);
            if (confirmation != System.Windows.MessageBoxResult.Yes)
                return new UninstallResult(UninstallOutcome.Canceled, "Удаление отменено.");
        }

        try
        {
            DeleteFileIfPresent(StartMenuShortcut);
            DeleteFileIfPresent(DesktopShortcut);
            Registry.CurrentUser.DeleteSubKeyTree(UninstallRegistryPath, throwOnMissingSubKey: false);

            string current = Path.GetFullPath(CurrentExecutable());
            string installed = Path.GetFullPath(InstalledExecutable);
            string license = Path.Combine(InstallDirectory, "LICENSE.txt");
            string stagedExecutable = installed + ".installing";

            if (string.Equals(current, installed, StringComparison.OrdinalIgnoreCase))
                ScheduleRemovalAfterExit(installed, license, stagedExecutable, InstallDirectory);
            else
            {
                DeleteFileIfPresent(installed);
                DeleteFileIfPresent(license);
                DeleteFileIfPresent(stagedExecutable);
                DeleteDirectoryIfEmpty(InstallDirectory);
            }

            return new UninstallResult(
                UninstallOutcome.Success,
                "PersonGuard удалён. Зашифрованные сейфы .pgd и личные настройки сохранены.");
        }
        catch (Exception ex)
        {
            return new UninstallResult(UninstallOutcome.Failure, $"Не удалось удалить PersonGuard: {ex.Message}");
        }
    }

    public static void LaunchInstalledApplication()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = InstalledExecutable,
            UseShellExecute = true,
            WorkingDirectory = InstallDirectory
        });
    }

    private static string StartMenuShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Programs),
        "PersonGuard.lnk");

    private static string DesktopShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "PersonGuard.lnk");

    private static bool IsRunningFromInstallDirectory()
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(CurrentExecutable()),
                Path.GetFullPath(InstalledExecutable),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsApplicationRunning()
    {
        try
        {
            if (!System.Threading.Mutex.TryOpenExisting(AppMutexName, out System.Threading.Mutex? mutex))
                return false;
            mutex.Dispose();
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static string CurrentExecutable()
    {
        string? path = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("Не удалось определить путь к установщику.");
        return Path.GetFullPath(path);
    }

    private static void RegisterUninstaller(string executable)
    {
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(UninstallRegistryPath, writable: true)
            ?? throw new InvalidOperationException("Не удалось зарегистрировать программу удаления.");

        long sizeBytes = new FileInfo(executable).Length + Encoding.UTF8.GetByteCount(LicenseInfo.Text);
        int estimatedKilobytes = checked((int)Math.Min(int.MaxValue, (sizeBytes + 1023L) / 1024L));
        key.SetValue("DisplayName", ProductName, RegistryValueKind.String);
        key.SetValue("DisplayVersion", Version, RegistryValueKind.String);
        key.SetValue("Publisher", Publisher, RegistryValueKind.String);
        key.SetValue("InstallLocation", InstallDirectory, RegistryValueKind.String);
        key.SetValue("DisplayIcon", executable, RegistryValueKind.String);
        key.SetValue("UninstallString", $"\"{executable}\" --uninstall", RegistryValueKind.String);
        key.SetValue("QuietUninstallString", $"\"{executable}\" --uninstall --quiet", RegistryValueKind.String);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture), RegistryValueKind.String);
        key.SetValue("EstimatedSize", estimatedKilobytes, RegistryValueKind.DWord);
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void CreateShortcut(string shortcutPath, string executable)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new PlatformNotSupportedException("Windows Script Host недоступен для создания ярлыка.");
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(shellType)
                ?? throw new InvalidOperationException("Не удалось открыть Windows Script Host.");
            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                BindingFlags.InvokeMethod,
                binder: null,
                target: shell,
                args: [shortcutPath]);
            if (shortcut is null)
                throw new InvalidOperationException("Не удалось создать ярлык PersonGuard.");

            Type shortcutType = shortcut.GetType();
            shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, [executable]);
            shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, [InstallDirectory]);
            shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, ["Локальный зашифрованный менеджер паролей"]);
            shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, [$"{executable},0"]);
            shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
        }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut))
                Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null && Marshal.IsComObject(shell))
                Marshal.FinalReleaseComObject(shell);
        }
    }

    private static void ScheduleRemovalAfterExit(params string[] paths)
    {
        int processId = Environment.ProcessId;
        string installedDirectory = Path.GetFullPath(InstallDirectory);
        string[] files = paths.Take(paths.Length - 1).Select(Path.GetFullPath).ToArray();
        string directory = Path.GetFullPath(paths[^1]);
        if (!string.Equals(directory, installedDirectory, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Небезопасный путь удаления отклонён.");

        static string QuotePowerShell(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

        var command = new StringBuilder();
        command.Append("try { Wait-Process -Id ").Append(processId).Append(" -Timeout 30 -ErrorAction SilentlyContinue } catch {};");
        foreach (string file in files)
        {
            if (!file.StartsWith(installedDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Небезопасный путь удаления отклонён.");
            command.Append("Remove-Item -LiteralPath ").Append(QuotePowerShell(file)).Append(" -Force -ErrorAction SilentlyContinue;");
        }
        command.Append("Remove-Item -LiteralPath ").Append(QuotePowerShell(directory)).Append(" -Force -ErrorAction SilentlyContinue;");

        string encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(command.ToString()));
        string powerShell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        Process.Start(new ProcessStartInfo
        {
            FileName = powerShell,
            Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }

    private static void DeleteFileIfPresent(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }

    private static void DeleteDirectoryIfEmpty(string path)
    {
        if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any())
            Directory.Delete(path);
    }
}

public static class LicenseInfo
{
    private static readonly Lazy<string> LicenseText = new(() =>
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("PersonGuard.LICENSE.txt")
            ?? throw new InvalidOperationException("Текст лицензии CC BY-NC-ND 4.0 не найден в приложении.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    });

    public static string Text => LicenseText.Value;
}
