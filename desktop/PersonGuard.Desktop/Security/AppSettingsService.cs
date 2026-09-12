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
    public bool LockOnMinimize { get; set; } = true;
    public bool LockOnFocusLoss { get; set; }
    public bool ReauthenticateSecrets { get; set; } = true;
    public int AutoLockMinutes { get; set; } = 3;
}

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
        byte[] protectedData = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser);
        CryptographicOperations.ZeroMemory(json);
        string temp = _path + ".tmp";
        try
        {
            File.WriteAllBytes(temp, protectedData);
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
            if (loaded is null) return new AppSecuritySettings();
            loaded.AutoLockMinutes = loaded.AutoLockMinutes is 0 or 1 or 3 or 5 or 15 ? loaded.AutoLockMinutes : 3;
            return loaded;
        }
        catch
        {
            return new AppSecuritySettings();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedData);
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
