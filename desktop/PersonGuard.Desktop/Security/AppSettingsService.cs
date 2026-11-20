using System.Security;
using System.Security.Cryptography;
using System.Text.Json;

namespace PersonGuard.Desktop.Security;

public sealed class AppSecuritySettings
{
    public bool AppPasswordEnabled { get; set; }
    public byte[] AppPasswordSalt { get; set; } = [];
    public byte[] AppPasswordHash { get; set; } = [];
    public bool WindowsHelloEnabled { get; set; }
    public bool ClipboardEnabled { get; set; }
    public bool ScreenCaptureProtection { get; set; } = true;
    public bool LockOnFocusLoss { get; set; }
    public int AutoLockMinutes { get; set; } = 3;

    public static int NormalizeAutoLock(int minutes) => minutes is 0 or 1 or 3 or 5 or 15 ? minutes : 3;

    public VaultPolicy ToPolicy() => new(ScreenCaptureProtection, ClipboardEnabled, LockOnFocusLoss, AutoLockMinutes);

    /// <summary>Local settings and the open vault's authenticated policy can only tighten each other.</summary>
    public void Tighten(VaultPolicy policy)
    {
        ScreenCaptureProtection |= policy.ScreenCaptureProtection;
        ClipboardEnabled &= policy.ClipboardEnabled;
        LockOnFocusLoss |= policy.LockOnFocusLoss;
        if (AutoLockMinutes == 0 || (policy.AutoLockMinutes != 0 && policy.AutoLockMinutes < AutoLockMinutes))
            AutoLockMinutes = policy.AutoLockMinutes;
    }
}

/// <summary>
/// Copy of the protection settings stored inside the encrypted vault. The local DPAPI settings file
/// is writable by any same-user process, so it alone must not be able to weaken an open vault.
/// </summary>
public sealed record VaultPolicy(bool ScreenCaptureProtection, bool ClipboardEnabled, bool LockOnFocusLoss, int AutoLockMinutes);

public sealed class AppSettingsService
{
    private static readonly byte[] Entropy = "PersonGuard.Settings.v2.Windows.CurrentUser"u8.ToArray();
    private readonly string _path;

    public AppSettingsService(string? settingsPath = null)
    {
        string defaultDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonGuard");
        string fullPath = Path.GetFullPath(settingsPath ?? Path.Combine(defaultDirectory, "security.pgcfg"));
        string directory = Path.GetDirectoryName(fullPath) ?? defaultDirectory;
        Directory.CreateDirectory(directory);
        _path = fullPath;
        Settings = Load();
    }

    public AppSecuritySettings Settings { get; }

    public async Task SetAppPasswordAsync(SecureString password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = await Task.Run(() => Argon2Kdf.Derive(password, salt, Argon2Kdf.AppMemoryKiB, Argon2Kdf.AppIterations, Argon2Kdf.AppParallelism));
        CryptographicOperations.ZeroMemory(Settings.AppPasswordSalt);
        CryptographicOperations.ZeroMemory(Settings.AppPasswordHash);
        Settings.AppPasswordSalt = salt;
        Settings.AppPasswordHash = hash;
        Settings.AppPasswordEnabled = true;
        Save();
    }

    public async Task<bool> VerifyAppPasswordAsync(SecureString password)
    {
        if (!Settings.AppPasswordEnabled || Settings.AppPasswordSalt.Length != 16 || Settings.AppPasswordHash.Length != 32) return false;
        byte[] actual = await Task.Run(() => Argon2Kdf.Derive(password, Settings.AppPasswordSalt, Argon2Kdf.AppMemoryKiB, Argon2Kdf.AppIterations, Argon2Kdf.AppParallelism));
        try { return CryptographicOperations.FixedTimeEquals(actual, Settings.AppPasswordHash); }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    public void RemoveAppPassword()
    {
        CryptographicOperations.ZeroMemory(Settings.AppPasswordSalt);
        CryptographicOperations.ZeroMemory(Settings.AppPasswordHash);
        Settings.AppPasswordSalt = [];
        Settings.AppPasswordHash = [];
        Settings.AppPasswordEnabled = false;
        Settings.WindowsHelloEnabled = false;
        Save();
    }

    public void Save()
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(Settings);
        byte[] protectedData = [];
        string temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            try { protectedData = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser); }
            finally { CryptographicOperations.ZeroMemory(json); }
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(protectedData);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedData);
            if (File.Exists(temp)) { try { File.Delete(temp); } catch { } }
        }
    }

    private AppSecuritySettings Load()
    {
        if (!File.Exists(_path)) return new AppSecuritySettings();
        byte[] protectedData = [];
        byte[] plain = [];
        try
        {
            protectedData = File.ReadAllBytes(_path);
            plain = ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.CurrentUser);
            AppSecuritySettings? loaded = JsonSerializer.Deserialize<AppSecuritySettings>(plain);
            if (loaded is null || loaded.AppPasswordSalt is null || loaded.AppPasswordHash is null ||
                (loaded.AppPasswordEnabled && (loaded.AppPasswordSalt.Length != 16 || loaded.AppPasswordHash.Length != 32)) ||
                (loaded.WindowsHelloEnabled && !loaded.AppPasswordEnabled))
                throw new InvalidDataException("Некорректные настройки защиты.");
            loaded.AutoLockMinutes = AppSecuritySettings.NormalizeAutoLock(loaded.AutoLockMinutes);
            return loaded;
        }
        catch (Exception error) when (error is CryptographicException or JsonException or IOException or UnauthorizedAccessException)
        {
            // Existing but unreadable security settings must never disable the app gate.
            throw new InvalidDataException("Не удалось прочитать настройки защиты. Запуск остановлен; файл security.pgcfg сохранён. Восстановите его из резервной копии для этого пользователя Windows.", error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedData);
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
