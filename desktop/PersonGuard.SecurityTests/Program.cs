using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shell;
using System.Windows.Threading;
using PersonGuard.Desktop.Dialogs;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;
using PersonGuard.Desktop.Storage;

int passed = 0;

if (args.Contains("--ui-benchmark"))
{
    UiPerformanceProbe.Run(args);
    return;
}

await RunAsync("Windows WebAuthn x64 ABI matches the Microsoft header", async () =>
{
    Assert(IntPtr.Size == 8, "PersonGuard WebAuthn requires x64.");
    foreach (var (name, size, field, offset) in new[]
    {
        ("MakeOptions", 104, "EnablePrf", 96),
        ("GetOptions", 120, "SaltValues", 104),
        ("Attestation", 136, "PrfEnabled", 128),
        ("Assertion", 120, "Secret", 112),
        ("Salt", 32, "First", 8),
        ("SaltValues", 24, "Items", 16),
        ("User", 40, "DisplayName", 32)
    })
    {
        Type type = typeof(PasskeyService).GetNestedType(name, BindingFlags.NonPublic)!;
        Assert(Marshal.SizeOf(type) == size, $"{name} native size mismatch: {Marshal.SizeOf(type)} != {size}.");
        Assert(Marshal.OffsetOf(type, field).ToInt32() == offset, $"{name}.{field} native offset mismatch.");
    }
    await Task.CompletedTask;
});

await RunAsync("PGD3 passkey, recovery, rotation, revocation and tampering", async () =>
{
    using SecureString master = Secure("Passkey Recovery Master! 2026");
    using SecureString next = Secure("Rotated Recovery Master! 2026");
    using var vault = TestVault();
    using var session = PgdCryptoService.CreateSession(master);
    byte[] prf = RandomNumberGenerator.GetBytes(32);
    byte[] wrong = RandomNumberGenerator.GetBytes(32);
    session.Passkey = PgdCryptoService.CreatePasskeyEnvelope(session, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), prf);
    Assert(PgdCryptoService.VerifyPasskey(session, prf), "Valid passkey reauthentication failed.");
    Assert(!PgdCryptoService.VerifyPasskey(session, wrong), "Wrong passkey reauthentication succeeded.");
    byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
    try
    {
        Assert(encrypted.AsSpan(0, 4).SequenceEqual("PGD3"u8), "Missing PGD3 marker.");
        Assert(!Contains(encrypted, prf), "PRF secret leaked.");
        var slot = PgdCryptoService.GetPasskey(encrypted)!;
        Assert(slot.CredentialId.SequenceEqual(session.Passkey.CredentialId), "Credential changed.");
        foreach (bool usePasskey in new[] { false, true })
        {
            var opened = usePasskey ? PgdCryptoService.OpenWithPasskey(encrypted, prf) : PgdCryptoService.Open(encrypted, master);
            using (opened.Session)
            using (opened.Vault)
            {
                Assert(opened.Session.Passkey is not null, "Slot lost after open.");
                Assert(opened.Vault.Entries[0].Password.RevealForDisplay() == "UltraSecret-Ж-2026!", "Passkey data mismatch.");
            }
        }
        Expect<CryptographicException>(() => PgdCryptoService.OpenWithPasskey(encrypted, wrong));
        Expect<CryptographicException>(() => PgdCryptoService.Open(encrypted, next));
        // Metadata substitution must fail even with a valid password or a working PRF key.
        byte[] changed = encrypted.ToArray();
        int idOffset = Encoding.UTF8.GetString(changed).IndexOf(Convert.ToBase64String(slot.CredentialId), StringComparison.Ordinal);
        Assert(idOffset > 0, "Credential metadata missing.");
        changed[idOffset] = changed[idOffset] == (byte)'A' ? (byte)'B' : (byte)'A';
        Expect<CryptographicException>(() => PgdCryptoService.Open(changed, master));
        Expect<CryptographicException>(() => PgdCryptoService.OpenWithPasskey(changed, prf));
        byte[] corruptBody = encrypted.ToArray();
        corruptBody[^1] ^= 1;
        Expect<CryptographicException>(() => PgdCryptoService.Open(corruptBody, master));
        Expect<CryptographicException>(() => PgdCryptoService.OpenWithPasskey(corruptBody, prf));
        // Stripping the PGD3 header cannot downgrade the authenticated payload to PGD2.
        int offset = 8 + BinaryPrimitives.ReadInt32BigEndian(encrypted.AsSpan(4, 4));
        Expect<CryptographicException>(() => PgdCryptoService.Open(encrypted.AsSpan(offset), master));
        byte[] malformed = encrypted.ToArray();
        BinaryPrimitives.WriteInt32BigEndian(malformed.AsSpan(4, 4), int.MaxValue);
        Expect<InvalidDataException>(() => PgdCryptoService.GetPasskey(malformed));
        Expect<InvalidDataException>(() => PgdCryptoService.GetPasskey(encrypted.AsSpan(0, 7)));
        byte[] oldKey = session.VaultKey.Reveal();
        PgdCryptoService.ChangeMasterPassword(session, next);
        byte[] newKey = session.VaultKey.Reveal();
        try { Assert(!oldKey.AsSpan().SequenceEqual(newKey), "Password change kept the data key: an old slot or leaked key still decrypts new saves."); }
        finally { CryptographicOperations.ZeroMemory(oldKey); CryptographicOperations.ZeroMemory(newKey); }
        Assert(session.Passkey is null, "Password change kept a slot that wraps the old key.");
        byte[] rotated = PgdCryptoService.Encrypt(vault, session);
        Expect<CryptographicException>(() => PgdCryptoService.Open(rotated, master));
        var recovered = PgdCryptoService.Open(rotated, next);
        recovered.Vault.Dispose(); recovered.Session.Dispose();
        Expect<InvalidDataException>(() => PgdCryptoService.OpenWithPasskey(rotated, prf));
        session.Passkey = PgdCryptoService.CreatePasskeyEnvelope(session, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), prf);
        byte[] readded = PgdCryptoService.Encrypt(vault, session);
        var unlocked = PgdCryptoService.OpenWithPasskey(readded, prf);
        unlocked.Vault.Dispose(); unlocked.Session.Dispose();
        session.Passkey = null;
        byte[] revoked = PgdCryptoService.Encrypt(vault, session);
        Assert(PgdCryptoService.GetPasskey(revoked) is null, "Revoked slot retained.");
        Expect<InvalidDataException>(() => PgdCryptoService.OpenWithPasskey(revoked, prf));
        var fallback = PgdCryptoService.Open(revoked, next);
        fallback.Vault.Dispose(); fallback.Session.Dispose();
    }
    finally { CryptographicOperations.ZeroMemory(prf); CryptographicOperations.ZeroMemory(wrong); CryptographicOperations.ZeroMemory(encrypted); }
    await Task.CompletedTask;
});

await RunAsync("In-memory secrets use process-bound encryption", async () =>
{
    FieldInfo storedField = typeof(ProtectedBytes).GetField("_protected", BindingFlags.Instance | BindingFlags.NonPublic)!;
    foreach (int length in new[] { 0, 1, 15, 16, 17, 32, 1000 })
    {
        byte[] secret = RandomNumberGenerator.GetBytes(length);
        var bytes = ProtectedBytes.FromBytes(secret);
        var stored = (byte[])storedField.GetValue(bytes)!;
        Assert(stored.Length % 16 == 0 && stored.Length > length, "Protected buffer is not block-aligned.");
        Assert(length < 16 || !Contains(stored, secret), "Secret stored in plaintext.");
        Assert(bytes.Reveal().AsSpan().SequenceEqual(secret), $"Round-trip changed a {length}-byte secret.");
        bytes.Dispose();
        Expect<ObjectDisposedException>(() => bytes.Reveal());
    }
    await Task.CompletedTask;
});

await RunAsync("Vault protection policy round-trips and only tightens local settings", async () =>
{
    using SecureString master = Secure("Policy Master Password! 2026");
    using var vault = TestVault();
    vault.Policy = new VaultPolicy(true, false, true, 1);
    using VaultSession session = PgdCryptoService.CreateSession(master);
    byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
    try
    {
        OpenVaultResult opened = PgdCryptoService.Open(encrypted, master);
        using (opened.Vault)
        using (opened.Session)
        {
            Assert(opened.Vault.Policy == vault.Policy, "Policy changed after round-trip.");
            var tampered = new AppSecuritySettings { ScreenCaptureProtection = false, ClipboardEnabled = true, LockOnFocusLoss = false, AutoLockMinutes = 0 };
            tampered.Tighten(opened.Vault.Policy!);
            Assert(tampered.ToPolicy() == vault.Policy, "Tampered local settings weakened the vault policy.");
        }
        var strict = new AppSecuritySettings { AutoLockMinutes = 1 };
        strict.Tighten(new VaultPolicy(false, true, false, 0));
        Assert(strict.ToPolicy() == new VaultPolicy(true, false, false, 1), "Vault policy loosened local settings.");
    }
    finally { CryptographicOperations.ZeroMemory(encrypted); }
    await Task.CompletedTask;
});

await RunAsync("PGD2 round-trip and full-field encryption", async () =>
{
    using SecureString master = Secure("Correct Horse Battery Staple! 2026");
    using var vault = TestVault();
    using VaultSession session = PgdCryptoService.CreateSession(master);
    byte[] first = PgdCryptoService.Encrypt(vault, session);
    byte[] second = PgdCryptoService.Encrypt(vault, session);
    try
    {
        Assert(first.AsSpan(0, 4).SequenceEqual("PGD2"u8), "Missing PGD2 marker.");
        Assert(!first.AsSpan().SequenceEqual(second), "Two saves reused the same ciphertext.");
        foreach (string secret in new[] { "Example Account", "vault.user@example.test", "UltraSecret-Ж-2026!", "+48 555 010 200", "https://example.test/login" })
            Assert(!Contains(first, Encoding.UTF8.GetBytes(secret)), $"Plaintext leaked: {secret}");

        OpenVaultResult opened = PgdCryptoService.Open(first, master);
        using (opened.Vault)
        using (opened.Session)
        {
            Assert(opened.Vault.Entries.Count == 1, "Entry count changed.");
            Assert(opened.Vault.Entries[0].Password.RevealForDisplay() == "UltraSecret-Ж-2026!", "Password changed after round-trip.");
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(first);
        CryptographicOperations.ZeroMemory(second);
    }
    await Task.CompletedTask;
});

await RunAsync("Service sign-in round-trip needs no password and keeps email grouping", async () =>
{
    using SecureString master = Secure("Federated Sign In Master! 2026");
    using var vault = new VaultDocument { Name = "Service Login Vault" };
    vault.Entries.Add(new VaultEntry
    {
        Title = "Design Account",
        Url = "https://design.example.test",
        Username = "icloud.owner@example.test",
        AuthProvider = LoginProvider.Apple,
        Password = ProtectedSecret.FromString(string.Empty),
        Strength = 0,
    });
    using VaultSession session = PgdCryptoService.CreateSession(master);
    byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
    try
    {
        OpenVaultResult opened = PgdCryptoService.Open(encrypted, master);
        using (opened.Vault)
        using (opened.Session)
        {
            VaultEntry entry = opened.Vault.Entries.Single();
            Assert(entry.AuthProvider == LoginProvider.Apple, "Apple sign-in provider changed after round-trip.");
            Assert(!entry.UsesPassword, "Service sign-in was treated as password sign-in.");
            Assert(entry.Password.RevealForDisplay().Length == 0, "A service sign-in unexpectedly received a password.");
            Assert(entry.EmailGroup == "icloud.owner@example.test", "Service sign-in was separated from normal email grouping.");
            Assert(entry.SignInSummary.Contains("Apple", StringComparison.Ordinal), "Service sign-in is not visible in the entry summary.");
        }
    }
    finally { CryptographicOperations.ZeroMemory(encrypted); }
    await Task.CompletedTask;
});

await RunAsync("Phone-only entry round-trip does not require a password", async () =>
{
    using var vault = new VaultDocument { Name = "Phone Vault" };
    vault.Entries.Add(new VaultEntry
    {
        Title = "Mobile account",
        Username = string.Empty,
        Phone = "+48 555 700 800",
        AuthProvider = LoginProvider.Password,
        Password = ProtectedSecret.FromString(string.Empty),
        Strength = 0,
    });

    byte[] json = VaultSerializer.Serialize(vault);
    try
    {
        using VaultDocument restored = VaultSerializer.Deserialize(json);
        VaultEntry entry = restored.Entries.Single();
        Assert(entry.Phone == "+48 555 700 800", "Phone-only entry lost its phone number.");
        Assert(entry.Username.Length == 0, "Phone-only entry unexpectedly received a username.");
        Assert(!entry.UsesPassword, "Empty password was exposed as a password sign-in.");
        Assert(entry.SignInSummary.Contains("телефону", StringComparison.Ordinal), "Phone sign-in is not visible in the entry summary.");
    }
    finally { CryptographicOperations.ZeroMemory(json); }
    await Task.CompletedTask;
});

await RunAsync("Reused passwords are marked with every affected entry", async () =>
{
    using var vault = new VaultDocument { Name = "Reuse Vault" };
    Add("GitHub", "same-secret");
    Add("Figma", "same-secret");
    Add("Mail", "unique-secret");

    IReadOnlyList<PasswordReuseAlert> alerts = PasswordReuseAnalyzer.Analyze(vault.Entries);
    Assert(alerts.Count == 1, "Duplicate-password group was not detected.");
    Assert(alerts[0].Entries.Count == 2, "Duplicate-password group has the wrong size.");
    Assert(vault.Entries[0].HasReusedPassword && vault.Entries[1].HasReusedPassword, "Affected entries were not marked as dangerous.");
    Assert(!vault.Entries[2].HasReusedPassword, "Unique password was marked as reused.");
    Assert(vault.Entries[0].PasswordReuseCount == 2 && vault.Entries[0].PasswordReuseRisk == .5, "Two-password reuse did not receive the yellow risk level.");
    Assert(PasswordRiskPalette.AccentHex(0) == "#57D69A", "Safe risk color is not green.");
    Assert(PasswordRiskPalette.AccentHex(.5) == "#E3C557", "Medium risk color is not yellow.");
    Assert(PasswordRiskPalette.AccentHex(.75) == "#F39A4B", "High risk color is not orange.");
    Assert(PasswordRiskPalette.AccentHex(1) == "#FF5C72", "Critical risk color is not red.");
    Assert(PasswordRiskPalette.AccentHex((0d + 1d) / 2) == "#E3C557", "A mixed safe/critical group is not yellow.");
    Assert(alerts[0].Message.Contains("GitHub", StringComparison.Ordinal) && alerts[0].Message.Contains("Figma", StringComparison.Ordinal), "Warning does not name every affected entry.");

    using var criticalVault = new VaultDocument { Name = "Critical Reuse Vault" };
    for (int i = 0; i < 4; i++) criticalVault.Entries.Add(new VaultEntry
    {
        Title = $"Critical {i}", Username = $"critical{i}@example.test",
        Password = ProtectedSecret.FromString("reused-four-times"), Strength = 3,
    });
    PasswordReuseAnalyzer.Analyze(criticalVault.Entries);
    Assert(criticalVault.Entries.All(entry => entry.PasswordReuseCount == 4 && entry.PasswordReuseRisk == 1), "Four-way reuse did not receive the red risk level.");

    void Add(string title, string password) => vault.Entries.Add(new VaultEntry
    {
        Title = title,
        Username = $"{title.ToLowerInvariant()}@example.test",
        Password = ProtectedSecret.FromString(password),
        Strength = 3,
    });
    await Task.CompletedTask;
});

await RunAsync("Entries without auth metadata remain password entries", async () =>
{
    byte[] legacyJson = Encoding.UTF8.GetBytes("""
        {"schemaVersion":2,"vaultId":"legacy","name":"Legacy","entries":[{"id":"one","title":"Old account","url":"","username":"old@example.test","password":"Old-Secret-2026!","phone":"","favorite":false,"strength":3}]}
        """);
    try
    {
        using VaultDocument vault = VaultSerializer.Deserialize(legacyJson);
        VaultEntry entry = vault.Entries.Single();
        Assert(entry.AuthProvider == LoginProvider.Password, "Legacy entry did not default to password sign-in.");
        Assert(entry.UsesPassword, "Legacy entry lost password controls.");
        Assert(entry.Password.RevealForDisplay() == "Old-Secret-2026!", "Legacy password changed during deserialization.");
    }
    finally { CryptographicOperations.ZeroMemory(legacyJson); }
    await Task.CompletedTask;
});

await RunAsync("Wrong password and tampering are rejected", async () =>
{
    using SecureString master = Secure("Correct Horse Battery Staple! 2026");
    using SecureString wrong = Secure("Definitely Wrong Password 2026!");
    using var vault = TestVault();
    using VaultSession session = PgdCryptoService.CreateSession(master);
    byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
    try
    {
        Expect<CryptographicException>(() => PgdCryptoService.Open(encrypted, wrong));
        encrypted[^1] ^= 0x80;
        Expect<CryptographicException>(() => PgdCryptoService.Open(encrypted, master));
    }
    finally { CryptographicOperations.ZeroMemory(encrypted); }
    await Task.CompletedTask;
});

await RunAsync("Master-password rotation invalidates the old password", async () =>
{
    using SecureString oldPassword = Secure("Old Master Password Is Long! 1");
    using SecureString newPassword = Secure("New Master Password Is Long! 2");
    using var vault = TestVault();
    using VaultSession session = PgdCryptoService.CreateSession(oldPassword);
    PgdCryptoService.ChangeMasterPassword(session, newPassword);
    byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
    try
    {
        Expect<CryptographicException>(() => PgdCryptoService.Open(encrypted, oldPassword));
        OpenVaultResult opened = PgdCryptoService.Open(encrypted, newPassword);
        opened.Vault.Dispose();
        opened.Session.Dispose();
    }
    finally { CryptographicOperations.ZeroMemory(encrypted); }
    await Task.CompletedTask;
});

await RunAsync("PGD1 compatibility migrates to authenticated PGD2", async () =>
{
    using SecureString master = Secure("Migration Master Password! 2026");
    using var vault = TestVault();
    byte[] legacy = CreateLegacyPgd1(vault, master);
    try
    {
        OpenVaultResult migrated = PgdCryptoService.Open(legacy, master);
        using (migrated.Vault)
        using (migrated.Session)
        {
            Assert(migrated.Session.MigratedFromV1, "Migration flag was not set.");
            byte[] upgraded = PgdCryptoService.Encrypt(migrated.Vault, migrated.Session);
            try
            {
                Assert(upgraded.AsSpan(0, 4).SequenceEqual("PGD2"u8), "Legacy file was not upgraded.");
                OpenVaultResult reopened = PgdCryptoService.Open(upgraded, master);
                reopened.Vault.Dispose();
                reopened.Session.Dispose();
            }
            finally { CryptographicOperations.ZeroMemory(upgraded); }
        }
    }
    finally { CryptographicOperations.ZeroMemory(legacy); }
    await Task.CompletedTask;
});

await RunAsync("Atomic file save leaves only encrypted data", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    string path = Path.Combine(directory, "vault.pgd");
    Directory.CreateDirectory(directory);
    try
    {
        using SecureString master = Secure("Atomic Save Master Password! 2026");
        using var vault = TestVault();
        using VaultSession session = PgdCryptoService.CreateSession(master);
        await VaultFileService.SaveAtomicAsync(path, vault, session);
        byte[] file = await VaultFileService.ReadAsync(path);
        try
        {
            Assert(!Contains(file, Encoding.UTF8.GetBytes("UltraSecret-Ж-2026!")), "Atomic save wrote plaintext.");
            Assert(Directory.GetFiles(directory).Length == 1, "Temporary save file remained.");
        }
        finally { CryptographicOperations.ZeroMemory(file); }
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("Local app password is DPAPI-protected and verifiable", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    string path = Path.Combine(directory, "security.pgcfg");
    Directory.CreateDirectory(directory);
    try
    {
        using SecureString password = Secure("Local Gate Password! 2026");
        using SecureString wrong = Secure("Wrong Local Gate Password!");
        var settings = new AppSettingsService(path);
        await settings.SetAppPasswordAsync(password);
        Assert(await settings.VerifyAppPasswordAsync(password), "Correct local password was rejected.");
        Assert(!await settings.VerifyAppPasswordAsync(wrong), "Wrong local password was accepted.");
        byte[] protectedSettings = await File.ReadAllBytesAsync(path);
        try { Assert(!Contains(protectedSettings, Encoding.UTF8.GetBytes("AppPasswordHash")), "Settings were not protected by DPAPI."); }
        finally { CryptographicOperations.ZeroMemory(protectedSettings); }
        var reloaded = new AppSettingsService(path);
        Assert(await reloaded.VerifyAppPasswordAsync(password), "Protected settings could not be reloaded.");
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("Corrupted security settings fail closed without overwriting the file", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    string path = Path.Combine(directory, "security.pgcfg");
    try
    {
        byte[] original = "damaged settings"u8.ToArray();
        await File.WriteAllBytesAsync(path, original);
        Expect<InvalidDataException>(() => new AppSettingsService(path));
        Assert((await File.ReadAllBytesAsync(path)).AsSpan().SequenceEqual(original), "Corrupted settings were overwritten.");
        var firstRun = new AppSettingsService(Path.Combine(directory, "new.pgcfg"));
        Assert(!firstRun.Settings.AppPasswordEnabled && !firstRun.Settings.ClipboardEnabled, "First-run defaults changed.");
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("DPAPI-valid settings with invalid authentication metadata are rejected", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    string path = Path.Combine(directory, "security.pgcfg");
    try
    {
        foreach (string json in new[] { "null", "{\"AppPasswordEnabled\":true}", "{\"WindowsHelloEnabled\":true}", "{\"AppPasswordSalt\":null}" })
        {
            byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(json),
                "PersonGuard.Settings.v2.Windows.CurrentUser"u8.ToArray(), DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(path, encrypted);
            Expect<InvalidDataException>(() => new AppSettingsService(path));
        }
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("Oversized vault files are rejected before reading", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    string path = Path.Combine(directory, "oversized.pgd");
    try
    {
        using (var file = File.Create(path)) file.SetLength(64L * 1024 * 1024 + 1);
        try { await VaultFileService.ReadAsync(path); throw new InvalidOperationException("Oversized file was accepted."); }
        catch (InvalidDataException) { }
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("Passwords preserve exact content and oversized secrets are not truncated", async () =>
{
    using var vault = TestVault();
    const string exact = "  Ж🔐 e\u0301 password\t ";
    vault.Entries[0].Password = ProtectedSecret.FromString(exact);
    byte[] serialized = VaultSerializer.Serialize(vault);
    try
    {
        using var restored = VaultSerializer.Deserialize(serialized);
        Assert(restored.Entries.Single().Password.RevealForDisplay() == exact, "Password content was normalized.");
    }
    finally { CryptographicOperations.ZeroMemory(serialized); }
    vault.Entries[0].Password = ProtectedSecret.FromString(new string('x', 1001));
    serialized = VaultSerializer.Serialize(vault);
    try { Expect<InvalidDataException>(() => VaultSerializer.Deserialize(serialized)); }
    finally { CryptographicOperations.ZeroMemory(serialized); }
    await Task.CompletedTask;
});

await RunAsync("Authenticode validation rejects unsigned and corrupted files", async () =>
{
    Assert(!NativeSecurity.HasTrustedSignature(Environment.ProcessPath!), "Unsigned test application was trusted.");
    string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    string path = Path.Combine(directory, "tampered.exe");
    try
    {
        string source = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, ".dotnet", "dotnet.exe"));
        Assert(NativeSecurity.HasTrustedSignature(source), "Microsoft-signed dotnet fixture did not pass offline Authenticode validation.");
        byte[] bytes = await File.ReadAllBytesAsync(source);
        bytes[1024] ^= 1;
        await File.WriteAllBytesAsync(path, bytes);
        Assert(!NativeSecurity.HasTrustedSignature(path), "Modified executable was trusted based only on its signer certificate.");
        Assert(!NativeSecurity.HasTrustedSignature(Path.Combine(directory, "missing.exe")), "Missing executable was trusted.");
    }
    finally { Directory.Delete(directory, recursive: true); }
});

await RunAsync("WPF views render and locking invalidates sensitive operations", async () =>
{
    string artifacts = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "build", "previews"));
    string previewPath = Path.Combine(artifacts, "ui-preview.png");
    string vaultPreviewPath = Path.Combine(artifacts, "ui-vault-preview.png");
    string graphPreviewPath = Path.Combine(artifacts, "ui-graph-preview.png");
    string securityPreviewPath = Path.Combine(artifacts, "ui-security-preview.png");
    string entryPreviewPath = Path.Combine(artifacts, "ui-entry-preview.png");
    Directory.CreateDirectory(artifacts);
    string settingsDirectory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(settingsDirectory);
    Exception? failure = null;
    var thread = new Thread(() =>
    {
        try
        {
            var application = new TestApp();
            application.InitializeComponent();
            application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var window = new PersonGuard.Desktop.MainWindow(new AppSettingsService(Path.Combine(settingsDirectory, "security.pgcfg"))) { Width = 1250, Height = 760 };
            window.Show();
            WindowChrome chrome = WindowChrome.GetWindowChrome(window) ?? throw new InvalidOperationException("Custom window chrome is missing.");
            Assert(chrome.GlassFrameThickness == new Thickness(0), "System glass frame can leave a white strip around the custom title bar.");
            Assert(TextOptions.GetTextFormattingMode(window) == TextFormattingMode.Display, "Window is not using display-optimized text formatting.");
            Assert(TextOptions.GetTextRenderingMode(window) == TextRenderingMode.ClearType, "Window is not using ClearType text rendering.");
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            window.Measure(new Size(1250, 760));
            window.Arrange(new Rect(0, 0, 1250, 760));
            window.UpdateLayout();
            SaveVisual(window, previewPath);

            using SecureString previewMaster = Secure("UI Preview Master Password! 2026");
            VaultDocument previewVault = PreviewVault();
            VaultSession previewSession = PgdCryptoService.CreateSession(previewMaster);
            MethodInfo replaceVault = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ReplaceOpenVault", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ReplaceOpenVault");
            replaceVault.Invoke(window, new object?[] { previewVault, previewSession, @"D:\Vaults\personal.pgd", false });
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Assert(((FrameworkElement)window.FindName("PasswordAlertsPanel")).Visibility == Visibility.Visible, "Duplicate-password alert is not visible in the vault.");
            SaveVisual(window, vaultPreviewPath);

            // The new grid must use the available width instead of fixed-size cards.
            window.Width = 980;
            window.UpdateLayout();
            Assert(window.EntryColumns == 2, "Minimum-width window should fit two entry columns.");
            SaveVisual(window, Path.Combine(artifacts, "ui-vault-compact-preview.png"), 980, 760);
            var search = (System.Windows.Controls.TextBox)window.FindName("SearchBox");
            search.Text = "no-such-account-42";
            Assert(((System.Windows.Controls.TextBlock)window.FindName("EmptyTitleText")).Text == "Ничего не найдено", "Filtered results incorrectly claim the vault is empty.");
            search.Clear();
            window.Width = 1250;
            window.UpdateLayout();
            UiRegressionChecks.Run(window, previewVault, artifacts);

            var entryDialog = new EntryDialog(window, null);
            entryDialog.Show();
            var providerPicker = (System.Windows.Controls.ComboBox)(typeof(EntryDialog).GetField("_authProvider", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(entryDialog)
                ?? throw new MissingFieldException("_authProvider"));
            providerPicker.SelectedIndex = 0;
            var showPassword = (System.Windows.Controls.CheckBox)(typeof(EntryDialog).GetField("_showPassword", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(entryDialog)
                ?? throw new MissingFieldException("_showPassword"));
            Assert(showPassword.Visibility == Visibility.Visible, "Show-password option is missing from password entry creation.");
            entryDialog.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            entryDialog.Measure(new Size(entryDialog.ActualWidth, entryDialog.ActualHeight));
            entryDialog.Arrange(new Rect(0, 0, entryDialog.ActualWidth, entryDialog.ActualHeight));
            entryDialog.UpdateLayout();
            SaveVisual(entryDialog, entryPreviewPath, (int)Math.Ceiling(entryDialog.ActualWidth), (int)Math.Ceiling(entryDialog.ActualHeight));
            entryDialog.Close();

            MethodInfo showGraph = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ShowGraphPage", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ShowGraphPage");
            showGraph.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            var graphCanvas = (System.Windows.Controls.Canvas)window.FindName("GraphCanvas");
            Assert(graphCanvas.CacheMode is null, "Graph remained raster-cached while idle.");
            var graphSurface = graphCanvas.Children.OfType<PersonGuard.Desktop.Presentation.GraphDrawingSurface>().Single();
            var graphLabels = graphSurface.Captions;
            foreach (string title in previewVault.Entries.Select(entry => entry.Title))
                Assert(graphLabels.Contains(title), $"Graph omitted entry: {title}");
            UIElement firstGraphElement = graphCanvas.Children[0];
            int graphRevision = graphSurface.Revision;
            showGraph.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Assert(ReferenceEquals(firstGraphElement, graphCanvas.Children[0]), "Unchanged graph was rebuilt when reopened.");
            Assert(graphSurface.Revision == graphRevision, "Unchanged graph drawing was recreated when reopened.");
            var graphTransform = (MatrixTransform)window.FindName("GraphTransform");
            double initialScale = graphTransform.Matrix.M11;
            MethodInfo zoomGraph = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ZoomGraphAt", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ZoomGraphAt");
            int graphElementCount = graphCanvas.Children.Count;
            zoomGraph.Invoke(window, new object[] { 1.18d, new Point(450, 200) });
            Assert(graphCanvas.Children.Count == graphElementCount && graphTransform.Matrix.M11 > initialScale, "Graph zoom rebuilt content or failed to change its cached transform.");
            var cameraAfterZoom = graphTransform.Matrix;
            typeof(PersonGuard.Desktop.MainWindow).GetMethod("ShowVaultPage", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            showGraph.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Assert(graphTransform.Matrix == cameraAfterZoom, "Switching tabs reset the graph camera.");
            Assert(graphSurface.Revision == graphRevision, "Switching tabs regenerated an unchanged graph.");
            MethodInfo fitGraph = typeof(PersonGuard.Desktop.MainWindow).GetMethod("FitGraphToViewport", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("FitGraphToViewport");
            fitGraph.Invoke(window, null);
            SaveVisual(window, graphPreviewPath);

            MethodInfo showSecurity = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ShowSecurityPage", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ShowSecurityPage");
            showSecurity.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            SaveVisual(window, securityPreviewPath);
            window.Width = 980;
            window.UpdateLayout();
            SaveVisual(window, Path.Combine(artifacts, "ui-security-compact-preview.png"), 980, 760);
            window.Width = 1250;
            window.UpdateLayout();

            var canceled = new PasswordDialog(window, "Test", "Cancel must clear entered secrets");
            canceled.Show();
            var canceledPassword = (System.Windows.Controls.PasswordBox)typeof(PasswordDialog).GetField("_password", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(canceled)!;
            canceledPassword.Password = "TEST-CANCELED-SECRET";
            canceled.Close();
            Assert(canceledPassword.SecurePassword.Length == 0, "Canceled dialog retained entered password.");

            var guard = typeof(PersonGuard.Desktop.MainWindow).GetMethod("IsCurrentSession", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var epochField = typeof(PersonGuard.Desktop.MainWindow).GetField("_securityEpoch", BindingFlags.Instance | BindingFlags.NonPublic)!;
            int epoch = (int)epochField.GetValue(window)!;
            Assert((bool)guard.Invoke(window, new object[] { previewSession, epoch })!, "Current session rejected.");
            Assert(!(bool)guard.Invoke(window, new object[] { previewSession, epoch - 1 })!, "Stale authorization epoch accepted.");
            previewVault.Entries[0].PasswordDisplay = "TEST-REVEALED-SECRET";
            previewVault.Entries[1].Id = previewVault.Entries[0].Id;
            previewVault.Entries[1].PasswordDisplay = "TEST-SECOND-REVEALED-SECRET";
            var hideLater = typeof(PersonGuard.Desktop.MainWindow).GetMethod("HidePasswordLater", BindingFlags.Instance | BindingFlags.NonPublic)!;
            hideLater.Invoke(window, new object[] { previewVault.Entries[0] });
            hideLater.Invoke(window, new object[] { previewVault.Entries[1] });
            var timers = (System.Collections.IDictionary)typeof(PersonGuard.Desktop.MainWindow).GetField("_revealTimers", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(window)!;
            Assert(timers.Count == 2, "Duplicate record IDs canceled another record's password-hide timer.");
            var lockVault = typeof(PersonGuard.Desktop.MainWindow).GetMethod("LockVaultAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var entriesView = (FrameworkElement)window.FindName("VaultView");
            VaultEntry disposedEntry = previewVault.Entries[0];
            search.Text = "GitHub";
            ((Task)lockVault.Invoke(window, new object[] { "Test lock", true })!).GetAwaiter().GetResult();
            Assert(entriesView.Visibility == Visibility.Collapsed, "Locked vault remained visible.");
            Assert(!entriesView.HasAnimatedProperties, "Hiding the vault left a running entrance animation.");
            Assert(!(bool)guard.Invoke(window, new object[] { previewSession, epoch })!, "Cleared session accepted a delayed authorization.");
            Assert(disposedEntry.PasswordDisplay != "TEST-REVEALED-SECRET", "Revealed secret remained after lock.");
            Assert(((System.Windows.Controls.ItemsControl)window.FindName("PasswordAlertsList")).ItemsSource is null, "Alerts retained vault records after lock.");
            Assert(((System.Windows.Controls.ItemsControl)window.FindName("EntriesList")).ItemsSource is null, "Resetting search rebound locked vault entries.");
            Assert(graphSurface.Captions.Count == 0, "Graph retained vault captions after locking.");
            window.Close();

            application.Shutdown();
        }
        catch (Exception error) { failure = error; }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
    Directory.Delete(settingsDirectory, recursive: true);
    if (failure is not null) throw new InvalidOperationException("WPF render failed.", failure);
    Assert(new FileInfo(previewPath).Length > 10_000, "WPF preview is unexpectedly empty.");
    Assert(new FileInfo(vaultPreviewPath).Length > 10_000, "Vault preview is unexpectedly empty.");
    Assert(new FileInfo(graphPreviewPath).Length > 10_000, "Graph preview is unexpectedly empty.");
    Assert(new FileInfo(securityPreviewPath).Length > 10_000, "Security preview is unexpectedly empty.");
    Assert(new FileInfo(entryPreviewPath).Length > 10_000, "Entry dialog preview is unexpectedly empty.");
    await Task.CompletedTask;
});

// Last: it changes this test process's own DACL.
await RunAsync("Process DACL denies same-user memory reads, injection and DACL rewrites", async () =>
{
    Assert(NativeSecurity.InstallFolderWritable(), "Writable test folder was not detected.");
    Assert(NativeSecurity.RestrictProcessAccess(), "Process DACL was not applied.");
    // An elevated shell with SeDebugPrivilege enabled bypasses every DACL; drop it to check as a standard same-user process.
    Assert(LookupPrivilegeValueW(null, "SeDebugPrivilege", out long luid), "SeDebugPrivilege LUID is unavailable.");
    Assert(OpenProcessToken(-1, 0x0020 /* TOKEN_ADJUST_PRIVILEGES */, out nint token), "Process token is unavailable.");
    AdjustTokenPrivileges(token, false, [1, (int)luid, (int)(luid >> 32), 0x4 /* SE_PRIVILEGE_REMOVED */], 0, 0, 0);
    CloseHandle(token);
    foreach (uint access in new uint[] { 0x0010 /* VM_READ */, 0x0020 /* VM_WRITE */, 0x0002 /* CREATE_THREAD */, 0x0040 /* DUP_HANDLE */, 0x00040000 /* WRITE_DAC */ })
    {
        nint denied = OpenProcess(access, false, Environment.ProcessId);
        if (denied != 0) { CloseHandle(denied); throw new InvalidOperationException($"Access 0x{access:X} is still granted."); }
    }
    nint limited = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, Environment.ProcessId);
    Assert(limited != 0, "Task Manager-level query access was removed.");
    CloseHandle(limited);
    await Task.CompletedTask;
});

Console.WriteLine($"PASS: {passed} tests");

[DllImport("kernel32.dll", SetLastError = true)]
static extern nint OpenProcess(uint access, bool inherit, int processId);

[DllImport("advapi32.dll", SetLastError = true)]
static extern bool OpenProcessToken(nint process, uint access, out nint token);

[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern bool LookupPrivilegeValueW(string? system, string name, out long luid);

// TOKEN_PRIVILEGES with one entry as int[]: Count, LUID low, LUID high, Attributes.
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool AdjustTokenPrivileges(nint token, bool disableAll, int[] state, int length, nint previous, nint returnLength);

[DllImport("kernel32.dll")]
static extern bool CloseHandle(nint handle);

async Task RunAsync(string name, Func<Task> test)
{
    if (args.Contains("--ui-only") && !name.StartsWith("WPF", StringComparison.Ordinal)) return;
    await test();
    passed++;
    Console.WriteLine($"[PASS] {name}");
}

static VaultDocument TestVault()
{
    var vault = new VaultDocument { Name = "Security Test Vault" };
    vault.Entries.Add(new VaultEntry
    {
        Title = "Example Account",
        Url = "https://example.test/login",
        Username = "vault.user@example.test",
        Phone = "+48 555 010 200",
        Password = ProtectedSecret.FromString("UltraSecret-Ж-2026!"),
        Strength = 4,
    });
    Assert(vault.Entries[0].HasUrl, "Valid HTTPS entry URL was not recognized as clickable.");
    return vault;
}

static VaultDocument PreviewVault()
{
    var vault = new VaultDocument { Name = "Личный сейф" };
    Add("GitHub", "https://github.com/login", "alexander.with-a-long-profile-name@private-mail.example.test", "+48 555 010 100", "Preview-GitHub-Secret!", true, 4);
    Add("Figma", "https://figma.com", "alexander.with-a-long-profile-name@private-mail.example.test", "", "Preview-GitHub-Secret!", true, 3);
    Add("Notion", "https://notion.so", "work@studio.dev", "", "Preview-GitHub-Secret!", false, 3);
    Add("Linear", "https://linear.app", "alex@proton.me", "", "", false, 0, LoginProvider.Google);
    Add("Домашний сервер", "", "administrator", "", "Preview-GitHub-Secret!", false, 2);
    return vault;

    void Add(string title, string url, string username, string phone, string password, bool favorite, int strength, string authProvider = LoginProvider.Password)
    {
        vault.Entries.Add(new VaultEntry
        {
            Title = title,
            Url = url,
            Username = username,
            AuthProvider = authProvider,
            Phone = phone,
            Password = ProtectedSecret.FromString(password),
            Favorite = favorite,
            Strength = strength,
        });
    }
}

static void SaveVisual(Visual visual, string path, int width = 1250, int height = 760)
{
    // Screenshots show the settled state without changing production animation settings.
    Settle(visual);
    var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
    bitmap.Render(visual);
    var encoder = new PngBitmapEncoder();
    encoder.Frames.Add(BitmapFrame.Create(bitmap));
    string stagedPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
    try
    {
        using (FileStream stream = File.Create(stagedPath)) encoder.Save(stream);
        File.Move(stagedPath, path, overwrite: true);
    }
    finally { if (File.Exists(stagedPath)) File.Delete(stagedPath); }

    static void Settle(DependencyObject node)
    {
        if (node is UIElement element) element.BeginAnimation(UIElement.OpacityProperty, null);
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(node); index++) Settle(VisualTreeHelper.GetChild(node, index));
    }
}

static SecureString Secure(string value)
{
    var result = new SecureString();
    foreach (char character in value) result.AppendChar(character);
    result.MakeReadOnly();
    return result;
}

static bool Contains(ReadOnlySpan<byte> data, ReadOnlySpan<byte> value) => data.IndexOf(value) >= 0;

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Expect<TException>(Action action) where TException : Exception
{
    try { action(); }
    catch (TException) { return; }
    throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
}

static byte[] CreateLegacyPgd1(VaultDocument vault, SecureString password)
{
    const int iterations = 310_000;
    const int headerSize = 40;
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    byte[] passwordBytes = SecureStringUtil.ToUtf8(password);
    byte[] key = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32);
    byte[] plaintext = VaultSerializer.Serialize(vault);
    byte[] header = new byte[headerSize];
    "PGD1"u8.CopyTo(header);
    header[4] = 1;
    header[5] = 1;
    header[6] = 1;
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), iterations);
    salt.CopyTo(header, 12);
    nonce.CopyTo(header, 28);
    byte[] encrypted = new byte[plaintext.Length + 16];
    try
    {
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, encrypted.AsSpan(0, plaintext.Length), encrypted.AsSpan(plaintext.Length, 16), header);
        byte[] output = new byte[header.Length + encrypted.Length];
        header.CopyTo(output, 0);
        encrypted.CopyTo(output, header.Length);
        return output;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(passwordBytes);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(encrypted);
    }
}
