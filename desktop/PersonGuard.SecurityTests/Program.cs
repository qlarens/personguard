using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shell;
using System.Windows.Threading;
using PersonGuard.Desktop.Dialogs;
using PersonGuard.Desktop.Installation;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;
using PersonGuard.Desktop.Storage;

int passed = 0;

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

await RunAsync("WPF startup view renders", async () =>
{
    string artifacts = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "desktop", "artifacts"));
    string previewPath = Path.Combine(artifacts, "ui-preview.png");
    string vaultPreviewPath = Path.Combine(artifacts, "ui-vault-preview.png");
    string graphPreviewPath = Path.Combine(artifacts, "ui-graph-preview.png");
    string securityPreviewPath = Path.Combine(artifacts, "ui-security-preview.png");
    string entryPreviewPath = Path.Combine(artifacts, "ui-entry-preview.png");
    string installerPreviewPath = Path.Combine(artifacts, "ui-installer-preview.png");
    Directory.CreateDirectory(artifacts);
    Exception? failure = null;
    var thread = new Thread(() =>
    {
        try
        {
            var application = new PersonGuard.Desktop.App();
            application.InitializeComponent();
            application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var window = new PersonGuard.Desktop.MainWindow { Width = 1250, Height = 760 };
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
            var graphLabels = graphCanvas.Children.OfType<System.Windows.Controls.TextBlock>().Select(label => label.Text).ToList();
            foreach (string title in previewVault.Entries.Select(entry => entry.Title))
                Assert(graphLabels.Contains(title), $"Graph omitted entry: {title}");
            UIElement firstGraphElement = graphCanvas.Children[0];
            showGraph.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Assert(ReferenceEquals(firstGraphElement, graphCanvas.Children[0]), "Unchanged graph was rebuilt when reopened.");
            var graphTransform = (MatrixTransform)window.FindName("GraphTransform");
            double initialScale = graphTransform.Matrix.M11;
            MethodInfo zoomGraph = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ZoomGraphAt", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ZoomGraphAt");
            int graphElementCount = graphCanvas.Children.Count;
            zoomGraph.Invoke(window, new object[] { 1.18d, new Point(450, 200) });
            Assert(graphCanvas.Children.Count == graphElementCount && graphTransform.Matrix.M11 > initialScale, "Graph zoom rebuilt content or failed to change its cached transform.");
            MethodInfo fitGraph = typeof(PersonGuard.Desktop.MainWindow).GetMethod("FitGraphToViewport", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("FitGraphToViewport");
            fitGraph.Invoke(window, null);
            SaveVisual(window, graphPreviewPath);

            MethodInfo showSecurity = typeof(PersonGuard.Desktop.MainWindow).GetMethod("ShowSecurityPage", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("ShowSecurityPage");
            showSecurity.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            SaveVisual(window, securityPreviewPath);
            window.Close();

            var installerWindow = new InstallerWindow();
            installerWindow.Show();
            installerWindow.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            var licenseText = (System.Windows.Controls.TextBox)installerWindow.FindName("LicenseTextBox");
            var acceptLicense = (System.Windows.Controls.CheckBox)installerWindow.FindName("AcceptLicenseCheckBox");
            var installButton = (System.Windows.Controls.Button)installerWindow.FindName("InstallButton");
            Assert(licenseText.Text.Contains("Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International", StringComparison.Ordinal), "Installer does not display the CC BY-NC-ND 4.0 license.");
            Assert(licenseText.Text.Contains("Clarence Everhart (qlarens)", StringComparison.Ordinal), "Installer has the wrong copyright holder.");
            Assert(!installButton.IsEnabled, "Installer allows installation before license acceptance.");
            acceptLicense.IsChecked = true;
            installerWindow.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Assert(installButton.IsEnabled, "Installer remains disabled after license acceptance.");
            installerWindow.Measure(new Size(760, 670));
            installerWindow.Arrange(new Rect(0, 0, 760, 670));
            installerWindow.UpdateLayout();
            SaveVisual(installerWindow, installerPreviewPath, 760, 670);
            installerWindow.Close();
            application.Shutdown();
        }
        catch (Exception error) { failure = error; }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
    if (failure is not null) throw new InvalidOperationException("WPF render failed.", failure);
    Assert(new FileInfo(previewPath).Length > 10_000, "WPF preview is unexpectedly empty.");
    Assert(new FileInfo(vaultPreviewPath).Length > 10_000, "Vault preview is unexpectedly empty.");
    Assert(new FileInfo(graphPreviewPath).Length > 10_000, "Graph preview is unexpectedly empty.");
    Assert(new FileInfo(securityPreviewPath).Length > 10_000, "Security preview is unexpectedly empty.");
    Assert(new FileInfo(entryPreviewPath).Length > 10_000, "Entry dialog preview is unexpectedly empty.");
    Assert(new FileInfo(installerPreviewPath).Length > 10_000, "Installer preview is unexpectedly empty.");
    await Task.CompletedTask;
});

Console.WriteLine($"PASS: {passed}/11 tests");

async Task RunAsync(string name, Func<Task> test)
{
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
    Add("GitHub", "https://github.com/login", "alex@proton.me", "+48 555 010 100", "Preview-GitHub-Secret!", true, 4);
    Add("Figma", "https://figma.com", "alex@proton.me", "", "Preview-GitHub-Secret!", true, 3);
    Add("Notion", "https://notion.so", "work@studio.dev", "", "Preview-Notion-Secret!", false, 3);
    Add("Linear", "https://linear.app", "alex@proton.me", "", "", false, 0, LoginProvider.Google);
    Add("Домашний сервер", "https://home.local", "administrator", "", "Preview-Server-Secret!", false, 2);
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
    var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
    bitmap.Render(visual);
    var encoder = new PngBitmapEncoder();
    encoder.Frames.Add(BitmapFrame.Create(bitmap));
    using FileStream stream = File.Create(path);
    encoder.Save(stream);
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
