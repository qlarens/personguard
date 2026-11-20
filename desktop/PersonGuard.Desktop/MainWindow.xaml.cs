using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using PersonGuard.Desktop.Dialogs;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;
using PersonGuard.Desktop.Storage;
using PersonGuard.Desktop.Presentation;

namespace PersonGuard.Desktop;

public partial class MainWindow : Window
{
    public static readonly DependencyProperty EntryColumnsProperty = DependencyProperty.Register(
        nameof(EntryColumns), typeof(int), typeof(MainWindow), new PropertyMetadata(2));
    public int EntryColumns { get => (int)GetValue(EntryColumnsProperty); set => SetValue(EntryColumnsProperty, value); }

    private void EntriesList_SizeChanged(object sender, SizeChangedEventArgs args) =>
        EntryColumns = Math.Clamp((int)(args.NewSize.Width / 300), 1, 4);

    private readonly AppSettingsService _settingsService;
    private readonly DispatcherTimer _inactivityTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private readonly Dictionary<VaultEntry, DispatcherTimer> _revealTimers = [];
    private VaultDocument? _vault;
    private VaultSession? _session;
    private string? _filePath;
    private string _filter = "all";
    private string? _selectedGroup;
    private const int EntryPageSize = 24;
    private List<VaultEntry> _filteredEntries = [];
    private readonly ObservableCollection<VaultEntry> _visibleEntries = [];
    private int _entryPageIndex;
    private bool _graphUpdateScheduled;
    private Size _lastGraphViewportSize;
    private readonly GraphDrawingSurface _graphDrawing = new();
    private bool _dirty;
    private bool _suppressAutoLock;
    private bool _loadingSettings;
    private bool _closingAfterSave;
    private bool _appUnlocked;
    private bool _helloAvailable;
    private bool _passkeyBusy;
    private bool _unlockBusy;
    private bool _vaultOperationBusy;
    private bool _locking;
    private bool _saving;
    private int _securityEpoch;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private double _graphZoom = 1;
    private Vector _graphPan;
    private Point _graphDragStart;
    private Vector _graphPanAtDragStart;
    private bool _graphDragging;
    private bool _graphNeedsFit = true;
    private bool _graphLayoutDirty = true;
    private double _graphWorldWidth;
    private double _graphWorldHeight;
    private Rect _graphContentBounds = Rect.Empty;
    private uint _clipboardSequence;
    private readonly DispatcherTimer _clipboardTimer = new();

    public MainWindow() : this(new AppSettingsService()) { }

    public MainWindow(AppSettingsService settingsService)
    {
        _settingsService = settingsService;
        InitializeComponent();
        _inactivityTimer.Tick += InactivityTimer_Tick;
        _inactivityTimer.Start();
        _clipboardTimer.Tick += (_, _) => ClearOwnedClipboard();
        SystemEvents.SessionSwitch += SystemEvents_SessionSwitch;
    }

    private AppSecuritySettings Settings => _settingsService.Settings;

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        SignatureStatusText.Text = NativeSecurity.SignatureStatus() + (NativeSecurity.InstallFolderWritable()
            ? "\n⚠ Папка программы доступна для записи без прав администратора: exe можно подменить. Установите PersonGuard в C:\\Program Files."
            : string.Empty);
        _helloAvailable = await WindowsHelloService.IsAvailableAsync();
        RefreshSecurityControls();
        bool protectedStart = Settings.AppPasswordEnabled || Settings.WindowsHelloEnabled;
        _appUnlocked = !protectedStart;
        WelcomeView.Visibility = protectedStart ? Visibility.Collapsed : Visibility.Visible;
        AppLockedView.Visibility = protectedStart ? Visibility.Visible : Visibility.Collapsed;
        VaultView.Visibility = Visibility.Collapsed;
    }

    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        NativeSecurity.RemoveSystemWindowBorder(this);
        UpdateWindowCorners();
        NativeSecurity.SetCaptureProtection(this, Settings.ScreenCaptureProtection);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) ToggleMaximize();
        else DragMove();
    }
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private async void UnlockApp_Click(object sender, RoutedEventArgs e)
    {
        if (_unlockBusy) return;
        _unlockBusy = true;
        int epoch = _securityEpoch;
        try
        {
            if (await UnlockApplicationAsync() && epoch == _securityEpoch)
            {
                _appUnlocked = true;
                AppLockedView.Visibility = Visibility.Collapsed;
                WelcomeView.Visibility = Visibility.Visible;
                _lastActivity = DateTimeOffset.UtcNow;
            }
        }
        finally { _unlockBusy = false; }
    }

    private async Task<bool> UnlockApplicationAsync()
    {
        if (Settings.AppPasswordEnabled)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                var dialog = new PasswordDialog(this, "Разблокировать PersonGuard", "Введите отдельный локальный пароль приложения.", "Пароль приложения");
                if (ShowSecureDialog(dialog) != true) return false;
                using SecureString password = dialog.TakePassword();
                Mouse.OverrideCursor = Cursors.Wait;
                bool valid;
                try { valid = await _settingsService.VerifyAppPasswordAsync(password); }
                finally { Mouse.OverrideCursor = null; }
                if (valid) break;
                MessageBox.Show(this, "Неверный пароль приложения.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
                if (attempt == 4) return false;
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(8, 1 << attempt)));
            }
        }
        if (Settings.WindowsHelloEnabled)
        {
            if (!_helloAvailable)
            {
                MessageBox.Show(this, "Windows Hello сейчас недоступен. Вход разрешён по локальному паролю приложения.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (!await WindowsHelloService.VerifyAsync(this, "Разблокировать PersonGuard")) return false;
        }
        return true;
    }

    private async void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        if (!_appUnlocked || _vaultOperationBusy) return;
        var dialog = new VaultCredentialsDialog(this);
        if (ShowSecureDialog(dialog) != true) return;
        using SecureString password = dialog.TakeMasterPassword();
        int epoch = _securityEpoch;
        _vaultOperationBusy = true;
        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            VaultSession session = await Task.Run(() => PgdCryptoService.CreateSession(password));
            if (!_appUnlocked || epoch != _securityEpoch) { session.Dispose(); return; }
            var now = DateTimeOffset.UtcNow;
            var vault = new VaultDocument { Name = dialog.VaultName, CreatedAt = now, UpdatedAt = now };
            ReplaceOpenVault(vault, session, null, dirty: true);
            await SaveVaultAsync(forceChoosePath: true);
        }
        catch (Exception ex) { ShowSafeError("Не удалось создать хранилище", ex); }
        finally { Mouse.OverrideCursor = null; _vaultOperationBusy = false; }
    }

    private async void OpenVault_Click(object sender, RoutedEventArgs e)
        => await OpenVaultAsync(false);

    private async void OpenVaultWithPasskey_Click(object sender, RoutedEventArgs e)
        => await OpenVaultAsync(true);

    private async Task OpenVaultAsync(bool usePasskey)
    {
        if (!_appUnlocked || _passkeyBusy || _vaultOperationBusy) return;
        var picker = new OpenFileDialog { Filter = "PersonGuard (*.pgd)|*.pgd", CheckFileExists = true, Multiselect = false, Title = "Открыть зашифрованный сейф" };
        _suppressAutoLock = true;
        bool? picked;
        try { picked = picker.ShowDialog(this); }
        finally { _suppressAutoLock = false; }
        if (picked != true) return;

        int epoch = _securityEpoch;
        _vaultOperationBusy = true;
        byte[] file = [];
        OpenVaultResult? pendingResult = null;
        try
        {
            file = await VaultFileService.ReadAsync(picker.FileName);
            if (!_appUnlocked || epoch != _securityEpoch) return;
            OpenVaultResult result;
            if (usePasskey)
            {
                var slot = PgdCryptoService.GetPasskey(file) ?? throw new InvalidDataException("Ключ входа ещё не подключён. Откройте сейф мастер-паролем и добавьте ключ в разделе «Безопасность».");
                byte[] prf = await RunPasskeyAsync(hwnd => PasskeyService.Evaluate(hwnd, slot.CredentialId, slot.Salt));
                try { result = PgdCryptoService.OpenWithPasskey(file, prf); }
                finally { CryptographicOperations.ZeroMemory(prf); }
                if (!_appUnlocked) { result.Vault.Dispose(); result.Session.Dispose(); return; }
            }
            else
            {
                var dialog = new PasswordDialog(this, "Открыть зашифрованный сейф", "Мастер‑пароль используется только для вывода ключа и не сохраняется.", "Мастер‑пароль файла");
                if (ShowSecureDialog(dialog) != true) return;
                using SecureString password = dialog.TakePassword();
                Mouse.OverrideCursor = Cursors.Wait;
                result = await Task.Run(() => PgdCryptoService.Open(file, password));
            }
            pendingResult = result;
            if (!_appUnlocked || epoch != _securityEpoch ||
                (Settings.WindowsHelloEnabled && _helloAvailable && !await WindowsHelloService.VerifyAsync(this, "Подтвердить открытие сейфа")) ||
                !_appUnlocked || epoch != _securityEpoch)
            {
                result.Vault.Dispose(); result.Session.Dispose(); return;
            }
            ReplaceOpenVault(result.Vault, result.Session, picker.FileName, result.Session.MigratedFromV1);
            pendingResult = null;
            if (result.Session.MigratedFromV1)
                MessageBox.Show(this, "Файл PGD1 открыт и подготовлен к безопасной миграции в PGD2. Нажмите «Сохранить».", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { ShowSafeError("Не удалось открыть сейф", ex); }
        finally
        {
            pendingResult?.Vault.Dispose();
            pendingResult?.Session.Dispose();
            CryptographicOperations.ZeroMemory(file);
            Mouse.OverrideCursor = null;
            _vaultOperationBusy = false;
        }
    }

    private void ReplaceOpenVault(VaultDocument vault, VaultSession session, string? path, bool dirty)
    {
        ClearVaultMemory();
        Title = "PersonGuard";
        _vault = vault;
        _session = session;
        // The vault's authenticated policy undoes a weakened local settings file.
        if (vault.Policy is { } policy) Settings.Tighten(policy);
        vault.Policy = Settings.ToPolicy();
        NativeSecurity.SetCaptureProtection(this, Settings.ScreenCaptureProtection);
        _filePath = path;
        _dirty = dirty;
        _filter = "all";
        _selectedGroup = null;
        _graphLayoutDirty = true;
        _graphNeedsFit = true;
        SearchBox.Text = string.Empty;
        WelcomeView.Visibility = Visibility.Collapsed;
        AppLockedView.Visibility = Visibility.Collapsed;
        VaultView.Visibility = Visibility.Visible;
        ShowVaultPage();
        RefreshVaultUi();
        _lastActivity = DateTimeOffset.UtcNow;
    }

    private async void SaveVault_Click(object sender, RoutedEventArgs e) => await SaveVaultAsync(forceChoosePath: false);

    private async Task<bool> SaveVaultAsync(bool forceChoosePath, bool reportErrors = true)
    {
        if (_vault is null || _session is null || _saving) return false;
        VaultDocument vault = _vault;
        VaultSession session = _session;
        string? target = _filePath;
        if (forceChoosePath || string.IsNullOrWhiteSpace(target))
        {
            var picker = new SaveFileDialog
            {
                Filter = "PersonGuard PGD2 (*.pgd)|*.pgd",
                DefaultExt = ".pgd",
                AddExtension = true,
                FileName = SafeFileName(_vault.Name) + ".pgd",
                Title = "Сохранить зашифрованный сейф",
            };
            _suppressAutoLock = true;
            bool? picked;
            try { picked = picker.ShowDialog(this); }
            finally { _suppressAutoLock = false; }
            if (picked != true) return false;
            target = picker.FileName;
        }

        try
        {
            if (_vault != vault || _session != session) return false;
            _saving = true;
            Mouse.OverrideCursor = Cursors.Wait;
            vault.UpdatedAt = DateTimeOffset.UtcNow;
            await VaultFileService.SaveAtomicAsync(target!, vault, session);
            if (_vault != vault || _session != session) return false;
            _filePath = target;
            SetDirty(false);
            RefreshVaultUi();
            return true;
        }
        catch (Exception ex) { if (reportErrors) ShowSafeError("Не удалось сохранить сейф", ex); return false; }
        finally { Mouse.OverrideCursor = null; _saving = false; }
    }

    private async void AddEntry_Click(object sender, RoutedEventArgs e) => await EditEntryAsync(null);
    private async void EditEntry_Click(object sender, RoutedEventArgs e) => await EditEntryAsync((sender as Button)?.Tag as VaultEntry);

    private async Task EditEntryAsync(VaultEntry? existing)
    {
        if (_vault is not { } vault || _locking) return;
        int epoch = _securityEpoch;
        var dialog = new EntryDialog(this, existing);
        if (ShowSecureDialog(dialog) != true) return;
        if (_vault != vault || _securityEpoch != epoch || _locking) return;
        if (dialog.DeleteRequested)
        {
            if (existing is not null) { _vault.Entries.Remove(existing); existing.Dispose(); MarkChanged(); }
            return;
        }

        ProtectedSecret? replacement = null;
        int strength = existing?.Strength ?? 0;
        if (!dialog.UsesPassword || (existing is null && !dialog.HasNewPassword))
        {
            strength = 0;
            replacement = ProtectedSecret.FromString(string.Empty);
        }
        else if (dialog.HasNewPassword)
        {
            using SecureString secret = dialog.TakeNewPassword();
            strength = PasswordPolicy.Score(secret);
            replacement = ProtectedSecret.FromSecureString(secret);
        }
        try
        {
            string normalizedUrl = EntryDialog.NormalizeUrl(dialog.Url) ?? string.Empty;
            if (existing is null)
            {
                var now = DateTimeOffset.UtcNow;
                var entry = new VaultEntry
                {
                    Title = dialog.EntryTitle, Url = normalizedUrl, Username = dialog.Username, Phone = dialog.Phone,
                    AuthProvider = dialog.AuthProvider, Favorite = dialog.Favorite,
                    Password = replacement ?? throw new InvalidOperationException("Данные входа отсутствуют."), Strength = strength,
                    CreatedAt = now, UpdatedAt = now,
                };
                replacement = null;
                _vault.Entries.Insert(0, entry);
            }
            else
            {
                existing.Title = dialog.EntryTitle; existing.Url = normalizedUrl; existing.Username = dialog.Username; existing.Phone = dialog.Phone; existing.AuthProvider = dialog.AuthProvider;
                existing.Favorite = dialog.Favorite; existing.UpdatedAt = DateTimeOffset.UtcNow; existing.Strength = strength;
                if (replacement is not null) { existing.Password = replacement; replacement = null; }
            }
            MarkChanged();
        }
        finally { replacement?.Dispose(); }
        await Task.CompletedTask;
    }

    private void Favorite_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not VaultEntry entry || !IsCurrentEntry(entry)) return;
        entry.Favorite = !entry.Favorite;
        entry.UpdatedAt = DateTimeOffset.UtcNow;
        if (_vault is not null) _vault.UpdatedAt = entry.UpdatedAt;
        SetDirty(true);
        // Favorites do not change credentials, groups, risk, or graph geometry.
        if (_filter == "favorite") RefreshEntries();
    }

    private void OpenEntryUrl_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not VaultEntry entry || !Uri.TryCreate(entry.Url, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)) return;
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception error)
        {
            Debug.WriteLine($"Unable to open entry URL: {error.GetType().Name}");
            MessageBox.Show(this, "Не удалось открыть сайт в браузере по умолчанию.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void RevealPassword_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not VaultEntry entry || !entry.UsesPassword || !await ReauthenticateSecretAsync("Показать пароль") || !IsCurrentEntry(entry)) return;
        entry.PasswordDisplay = entry.Password.RevealForDisplay();
        HidePasswordLater(entry);
    }

    private void HidePasswordLater(VaultEntry entry)
    {
        if (_revealTimers.Remove(entry, out DispatcherTimer? old)) old.Stop();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(7) };
        timer.Tick += (_, _) => { timer.Stop(); entry.HidePassword(); _revealTimers.Remove(entry); GC.Collect(0, GCCollectionMode.Optimized); };
        _revealTimers[entry] = timer;
        timer.Start();
    }

    private async void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not VaultEntry entry || !entry.UsesPassword) return;
        if (!Settings.ClipboardEnabled) { MessageBox.Show(this, "Режим без буфера обмена включён. Разрешить копирование можно в разделе «Безопасность».", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (!await ReauthenticateSecretAsync("Скопировать пароль") || !IsCurrentEntry(entry) || !Settings.ClipboardEnabled) return;
        string value = entry.Password.RevealForDisplay();
        CopyWithAutoClear(value);
    }
    private async void CopyUsername_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is VaultEntry entry && Settings.ClipboardEnabled && await ReauthenticateSecretAsync("Скопировать username") && IsCurrentEntry(entry) && Settings.ClipboardEnabled) CopyWithAutoClear(entry.Username);
        else if (!Settings.ClipboardEnabled) MessageBox.Show(this, "Копирование отключено строгим режимом.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
    }
    private async void CopyPhone_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is VaultEntry entry && Settings.ClipboardEnabled && await ReauthenticateSecretAsync("Скопировать телефон") && IsCurrentEntry(entry) && Settings.ClipboardEnabled) CopyWithAutoClear(entry.Phone);
        else if (!Settings.ClipboardEnabled) MessageBox.Show(this, "Копирование отключено строгим режимом.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyWithAutoClear(string value)
    {
        if (!SensitiveClipboard.TrySetText(this, value, out uint sequence))
        {
            MessageBox.Show(this, "Не удалось безопасно открыть буфер обмена.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _clipboardSequence = sequence;
        _clipboardTimer.Stop();
        _clipboardTimer.Interval = TimeSpan.FromSeconds(20);
        _clipboardTimer.Start();
        FeedbackText.Text = "Скопировано · очистка через 20 секунд";
    }

    private void ClearOwnedClipboard()
    {
        if (SensitiveClipboard.TryClear(this, _clipboardSequence))
        {
            _clipboardSequence = 0;
            _clipboardTimer.Stop();
            FeedbackText.Text = string.Empty;
        }
        else
        {
            // Retry a busy clipboard without keeping any plaintext in managed state.
            _clipboardTimer.Interval = TimeSpan.FromSeconds(1);
            _clipboardTimer.Start();
        }
    }

    private bool IsCurrentEntry(VaultEntry entry) => !_locking && _vault?.Entries.Contains(entry) == true;
    private bool IsCurrentSession(VaultSession session, int epoch) =>
        !_locking && _session == session && _securityEpoch == epoch;

    private async Task<bool> ReauthenticateSecretAsync(string action, bool masterPasswordOnly = false)
    {
        if (_session is not { } session || _locking) return false;
        int epoch = _securityEpoch;
        if (!masterPasswordOnly && Settings.WindowsHelloEnabled && _helloAvailable)
            return await WindowsHelloService.VerifyAsync(this, action + " в PersonGuard") && IsCurrentSession(session, epoch);

        if (!masterPasswordOnly && _session.Passkey is { } slot && PasskeyService.IsAvailable)
        {
            try
            {
                byte[] prf = await RunPasskeyAsync(hwnd => PasskeyService.Evaluate(hwnd, slot.CredentialId, slot.Salt));
                try { return IsCurrentSession(session, epoch) && PgdCryptoService.VerifyPasskey(session, prf); }
                finally { CryptographicOperations.ZeroMemory(prf); }
            }
            catch (Exception ex) { ShowSafeError("Подтверждение ключом входа недоступно", ex); }
            if (!IsCurrentSession(session, epoch)) return false;
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (!IsCurrentSession(session, epoch)) return false;
            var dialog = new PasswordDialog(this, action, "Для чувствительного действия повторно введите мастер‑пароль файла.", "Мастер‑пароль файла");
            if (ShowSecureDialog(dialog) != true) return false;
            if (!IsCurrentSession(session, epoch)) return false;
            using SecureString password = dialog.TakePassword();
            Mouse.OverrideCursor = Cursors.Wait;
            bool valid;
            try { valid = await Task.Run(() => PgdCryptoService.VerifyMasterPassword(session, password)); }
            catch (ObjectDisposedException) { return false; }
            finally { Mouse.OverrideCursor = null; }
            if (!IsCurrentSession(session, epoch)) return false;
            if (valid) return true;
            MessageBox.Show(this, "Неверный мастер‑пароль.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            await Task.Delay(TimeSpan.FromSeconds(1 << attempt));
        }
        return false;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) { if (_vault is not null) RefreshEntries(resetPage: true); }
    private void Filter_Click(object sender, RoutedEventArgs e) { _filter = (sender as Button)?.Tag as string ?? "all"; _selectedGroup = null; ShowVaultPage(); RefreshEntries(resetPage: true); }
    private void Group_Click(object sender, RoutedEventArgs e) { _selectedGroup = (sender as Button)?.Tag as string; _filter = "all"; ShowVaultPage(); PageTitleText.Text = _selectedGroup ?? "Все записи"; RefreshEntries(resetPage: true); }
    private void ShowVaultPage_Click(object sender, RoutedEventArgs e) => ShowVaultPage();
    private void ShowGraphPage_Click(object sender, RoutedEventArgs e) => ShowGraphPage();
    private void ShowSecurityPage_Click(object sender, RoutedEventArgs e) => ShowSecurityPage();

    private void ShowVaultPage()
    {
        SearchRegion.Visibility = Visibility.Visible;
        ShowContentPage(EntriesPage);
        SearchBox.Visibility = Visibility.Visible; AddEntryButton.Visibility = Visibility.Visible;
        BreadcrumbText.Text = "PERSONGUARD / ХРАНИЛИЩЕ"; PageTitleText.Text = _selectedGroup ?? "Все записи";
        SetActiveNav(VaultNavButton);
    }
    private void ShowGraphPage()
    {
        SearchRegion.Visibility = Visibility.Collapsed;
        ShowContentPage(GraphPage);
        SearchBox.Visibility = Visibility.Collapsed; AddEntryButton.Visibility = Visibility.Visible;
        BreadcrumbText.Text = "PERSONGUARD / КАРТА"; PageTitleText.Text = "Схема связей"; SetActiveNav(GraphNavButton);
        RequestGraphUpdate();
    }
    private void ShowSecurityPage()
    {
        SearchRegion.Visibility = Visibility.Collapsed;
        ShowContentPage(SecurityPage);
        SearchBox.Visibility = Visibility.Collapsed; AddEntryButton.Visibility = Visibility.Collapsed;
        BreadcrumbText.Text = "PERSONGUARD / НАСТРОЙКИ"; PageTitleText.Text = "Безопасность"; SetActiveNav(SecurityNavButton); RefreshSecurityControls();
    }
    private void ShowContentPage(FrameworkElement active)
    {
        // These pages share the same grid cell. Hidden keeps their settled layout;
        // only the visible page accepts input or renders. Lock still collapses the whole vault.
        foreach (FrameworkElement page in new FrameworkElement[] { EntriesPage, GraphPage, SecurityPage })
            page.Visibility = page == active ? Visibility.Visible : Visibility.Hidden;
    }
    private void SetActiveNav(Button active)
    {
        foreach (Button button in new[] { VaultNavButton, GraphNavButton, SecurityNavButton })
        {
            button.Background = button == active ? new SolidColorBrush(Color.FromRgb(20, 32, 58)) : Brushes.Transparent;
            button.Foreground = button == active ? (Brush)FindResource("Text") : (Brush)FindResource("Muted");
        }
    }

    private void RefreshVaultUi()
    {
        if (_vault is null) return;
        VaultNameText.Text = _vault.Name;
        FilePathText.Text = _filePath ?? "Файл ещё не выбран";
        int count = _vault.Entries.Count;
        int groups = _vault.Entries.Where(e => VaultEntry.IsEmail(e.Username)).Select(e => e.EmailGroup).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        IReadOnlyList<PasswordReuseAlert> reuseAlerts = PasswordReuseAnalyzer.Analyze(_vault.Entries);
        int passwordCount = _vault.Entries.Count(e => e.UsesPassword);
        int strong = _vault.Entries.Count(e => e.UsesPassword && e.Strength >= 3 && !e.HasReusedPassword);
        TotalMetric.Text = count.ToString("00"); GroupsMetric.Text = groups.ToString("00"); HealthMetric.Text = passwordCount == 0 ? "—" : $"{strong * 100 / passwordCount}%";
        PasswordAlertsPanel.Visibility = reuseAlerts.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        PasswordAlertsList.ItemsSource = reuseAlerts;
        GroupsList.ItemsSource = _vault.Entries.Where(e => VaultEntry.IsEmail(e.Username)).GroupBy(e => e.EmailGroup, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key).Select(g => new EmailGroup(g.Key, g.Count(), g.Key[..1].ToUpperInvariant())).ToList();
        RefreshEntries(refreshCards: true);
        if (GraphPage.Visibility == Visibility.Visible && _graphLayoutDirty) DrawGraph();
    }

    private void RefreshEntries(bool resetPage = false, bool refreshCards = false)
    {
        if (_vault is null) return;
        string query = SearchBox.Text.Trim();
        IEnumerable<VaultEntry> filtered = _vault.Entries;
        if (_selectedGroup is not null) filtered = filtered.Where(e => string.Equals(e.EmailGroup, _selectedGroup, StringComparison.OrdinalIgnoreCase));
        if (_filter == "favorite") filtered = filtered.Where(e => e.Favorite);
        if (_filter == "weak") filtered = filtered.Where(e => e.UsesPassword && (e.Strength < 3 || e.HasReusedPassword));
        if (query.Length > 0) filtered = filtered.Where(e => e.Title.Contains(query, StringComparison.OrdinalIgnoreCase) || e.Username.Contains(query, StringComparison.OrdinalIgnoreCase) || e.Url.Contains(query, StringComparison.OrdinalIgnoreCase) || e.SignInSummary.Contains(query, StringComparison.OrdinalIgnoreCase));
        _filteredEntries = filtered.ToList();
        if (resetPage) _entryPageIndex = 0;
        DisplayEntryPage(refreshCards);
        bool isEmpty = _vault.Entries.Count == 0;
        EmptyTitleText.Text = isEmpty ? "Здесь начинается порядок" : "Ничего не найдено";
        EmptyDescriptionText.Text = isEmpty ? "Добавьте первую запись в свой личный сейф." : "Попробуйте другой запрос или измените фильтр.";
        EmptyActionButton.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
        foreach (Button filterButton in new[] { AllFilterButton, FavoriteFilterButton, WeakFilterButton })
        {
            bool selected = filterButton.Tag?.ToString() == _filter;
            filterButton.Background = selected ? (Brush)FindResource("Blue") : Brushes.Transparent;
            filterButton.Foreground = selected ? new SolidColorBrush(Color.FromRgb(7, 17, 43)) : (Brush)FindResource("Muted");
        }
        EmptyState.Visibility = _filteredEntries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EntriesList.Visibility = _filteredEntries.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        ResultText.Text = EntryCountText(_filteredEntries.Count);
    }

    private void DisplayEntryPage(bool refreshCards = false)
    {
        int count = _filteredEntries.Count;
        int pages = Math.Max(1, (count + EntryPageSize - 1) / EntryPageSize);
        _entryPageIndex = Math.Clamp(_entryPageIndex, 0, pages - 1);
        int start = _entryPageIndex * EntryPageSize;
        List<VaultEntry> page = _filteredEntries.Skip(start).Take(EntryPageSize).ToList();
        // Typing another prefix often leaves the same first page. Keep those controls,
        // while record edits explicitly refresh cards because some model fields are plain properties.
        if (!ReferenceEquals(EntriesList.ItemsSource, _visibleEntries)) EntriesList.ItemsSource = _visibleEntries;
        if (refreshCards) _visibleEntries.Clear();
        for (int index = 0; index < page.Count; index++)
        {
            if (index >= _visibleEntries.Count) _visibleEntries.Add(page[index]);
            else if (!ReferenceEquals(_visibleEntries[index], page[index])) _visibleEntries[index] = page[index];
        }
        while (_visibleEntries.Count > page.Count) _visibleEntries.RemoveAt(_visibleEntries.Count - 1);
        EntryPager.Visibility = count > EntryPageSize ? Visibility.Visible : Visibility.Collapsed;
        PreviousEntriesButton.IsEnabled = _entryPageIndex > 0;
        NextEntriesButton.IsEnabled = _entryPageIndex + 1 < pages;
        PageRangeText.Text = $"{start + 1}–{Math.Min(start + EntryPageSize, count)} из {count} · страница {_entryPageIndex + 1} из {pages}";
    }

    private void PreviousEntries_Click(object sender, RoutedEventArgs e) => ChangeEntryPage(-1);
    private void NextEntries_Click(object sender, RoutedEventArgs e) => ChangeEntryPage(1);

    private void ChangeEntryPage(int direction)
    {
        double offset = EntriesPage.VerticalOffset;
        _entryPageIndex += direction;
        DisplayEntryPage();
        // Restore after measuring the new cards; the last page may have a shorter extent.
        EntriesPage.UpdateLayout();
        EntriesPage.ScrollToVerticalOffset(Math.Min(offset, EntriesPage.ScrollableHeight));
    }

    private void MarkChanged()
    {
        if (_vault is not null) _vault.UpdatedAt = DateTimeOffset.UtcNow;
        _graphLayoutDirty = true;
        _graphNeedsFit = true;
        SetDirty(true); RefreshVaultUi();
    }
    private void SetDirty(bool value) { _dirty = value; DirtyText.Text = value ? "Есть несохранённые изменения" : "Все изменения сохранены"; DirtyText.Foreground = value ? new SolidColorBrush(Color.FromRgb(214, 171, 99)) : new SolidColorBrush(Color.FromRgb(93, 104, 122)); }

    private void DrawGraph()
    {
        GraphCanvas.Children.Clear();
        _graphDrawing.Clear();
        _graphContentBounds = Rect.Empty;
        if (_vault is null) return;
        var groups = _vault.Entries.Where(e => VaultEntry.IsEmail(e.Username)).GroupBy(e => e.EmailGroup, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Name: g.Key, Entries: g.OrderBy(entry => entry.Title, StringComparer.CurrentCultureIgnoreCase).ToList()))
            .OrderByDescending(group => group.Entries.Count).ThenBy(group => group.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var other = _vault.Entries.Where(e => !VaultEntry.IsEmail(e.Username)).OrderBy(entry => entry.Title, StringComparer.CurrentCultureIgnoreCase).ToList();
        if (other.Count > 0) groups.Add(("Другие записи", other));
        GraphEmpty.Visibility = groups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (groups.Count == 0)
        {
            _graphWorldWidth = _graphWorldHeight = 0;
            _graphLayoutDirty = false;
            return;
        }
        if (GraphViewport.ActualWidth < 100 || GraphViewport.ActualHeight < 100) return;

        double maxClusterRadius = groups.Max(group => GraphClusterRadius(group.Entries.Count));
        double groupRingX = groups.Count == 1
            ? 230
            : Math.Max(310, groups.Count * (maxClusterRadius * 2 + 105) / 5.2);
        // Reserve space for the vault circle AND its caption on both axes.
        // Dense groups must not expand inward across the central node.
        double centralClearance = maxClusterRadius + 180;
        groupRingX = Math.Max(groupRingX, centralClearance);
        double groupRingY = Math.Max(centralClearance, groupRingX * .48);
        _graphWorldWidth = Math.Max(820, (groupRingX + maxClusterRadius + 80) * 2);
        _graphWorldHeight = Math.Max(560, (groupRingY + maxClusterRadius + 35) * 2);
        GraphCanvas.Width = _graphWorldWidth;
        GraphCanvas.Height = _graphWorldHeight;
        GraphCanvas.CacheMode = null;
        double cx = _graphWorldWidth / 2, cy = _graphWorldHeight / 2;

        GraphCanvas.Children.Add(_graphDrawing);
        _graphDrawing.Draw(new Size(_graphWorldWidth, _graphWorldHeight), () =>
        {
            AddOrbit(cx, cy, Math.Max(105, groupRingX * .48), Math.Max(70, groupRingY * .48), Color.FromArgb(34, 91, 127, 255));
            AddOrbit(cx, cy, groupRingX, groupRingY, Color.FromArgb(26, 75, 217, 206));
            var positions = new List<Point>();
            for (int i = 0; i < groups.Count; i++)
            {
                double angle = groups.Count switch { 1 => -Math.PI / 2, 2 => i * Math.PI, _ => -Math.PI / 2 + i * Math.PI * 2 / groups.Count };
                positions.Add(new Point(cx + Math.Cos(angle) * groupRingX, cy + Math.Sin(angle) * groupRingY));
            }
            for (int i = 0; i < positions.Count; i++)
            {
                double groupRisk = groups[i].Entries.Average(entry => entry.PasswordReuseRisk);
                Color groupAccent = PasswordRiskPalette.AccentColor(groupRisk);
                AddWebLine(cx, cy, positions[i].X, positions[i].Y, WithAlpha(groupAccent, 125), 1.35 + groupRisk * .7);
            }
            for (int groupIndex = 0; groupIndex < groups.Count; groupIndex++)
            {
                var group = groups[groupIndex]; Point gp = positions[groupIndex];
                double groupRisk = group.Entries.Average(entry => entry.PasswordReuseRisk);
                Color groupAccent = PasswordRiskPalette.AccentColor(groupRisk);
                Color groupFill = PasswordRiskPalette.BackgroundColor(groupRisk);
                int entryIndex = 0;
                int ringIndex = 0;
                while (entryIndex < group.Entries.Count)
                {
                    double siteRadius = 82 + ringIndex * 62;
                    int capacity = Math.Max(6, (int)Math.Floor(Math.PI * 2 * siteRadius / 82));
                    int ringCount = Math.Min(capacity, group.Entries.Count - entryIndex);
                    for (int i = 0; i < ringCount; i++, entryIndex++)
                    {
                        VaultEntry entry = group.Entries[entryIndex];
                        double angle = -Math.PI / 2 + i * Math.PI * 2 / ringCount + groupIndex * .17 + ringIndex * .11;
                        double x = gp.X + Math.Cos(angle) * siteRadius, y = gp.Y + Math.Sin(angle) * siteRadius;
                        Color siteStroke = PasswordRiskPalette.AccentColor(entry.PasswordReuseRisk);
                        Color siteFill = PasswordRiskPalette.BackgroundColor(entry.PasswordReuseRisk);
                        AddLine(gp.X, gp.Y, x, y, WithAlpha(siteStroke, (byte)(95 + entry.PasswordReuseRisk * 70)), 1 + entry.PasswordReuseRisk * .8);
                        string initial = string.IsNullOrWhiteSpace(entry.Title) ? "?" : entry.Title[..1].ToUpperInvariant();
                        AddNode(x, y, 16, siteFill, siteStroke, initial, entry.Title, 128,
                            $"{entry.Title}\n{(!string.IsNullOrWhiteSpace(entry.Username) ? entry.Username : entry.Phone)}{(entry.HasReusedPassword ? $"\n⚠ Один пароль в {entry.PasswordReuseCount} записях" : "\nУникальный пароль")}", .14 + entry.PasswordReuseRisk * .24);
                    }
                    ringIndex++;
                }
                int riskyEntries = group.Entries.Count(entry => entry.HasReusedPassword);
                AddNode(gp.X, gp.Y, 27, groupFill, groupAccent, group.Name == "Другие записи" ? "◇" : "@", group.Name, 230,
                    $"{group.Name}\n{EntryCountText(group.Entries.Count)}\nПовторы: {riskyEntries}", .18 + groupRisk * .26);
            }
            AddNode(cx, cy, 38, Color.FromRgb(18, 31, 66), Color.FromRgb(111, 145, 255), "PG", _vault.Name, 200,
                $"{_vault.Name}\n{EntryCountText(_vault.Entries.Count)}", .24);

        });

        _graphLayoutDirty = false;
        if (_graphNeedsFit)
            FitGraphToViewport();
        else
            ApplyGraphTransform();
    }

    private void AddLine(double x1, double y1, double x2, double y2, Color color, double thickness) => _graphDrawing.Line(x1, y1, x2, y2, color, thickness);
    private void AddWebLine(double x1, double y1, double x2, double y2, Color color, double thickness) => _graphDrawing.WebLine(x1, y1, x2, y2, color, thickness);
    private void AddOrbit(double cx, double cy, double radiusX, double radiusY, Color color)
    {
        _graphDrawing.Orbit(cx, cy, radiusX, radiusY, color);
        TrackGraphBounds(new Rect(cx - radiusX, cy - radiusY, radiusX * 2, radiusY * 2));
    }
    private void AddNode(double x, double y, double radius, Color fill, Color stroke, string label, string caption, double captionWidth, string toolTip, double glowOpacity)
    {
        _graphDrawing.Node(x, y, radius, fill, stroke, label, caption, captionWidth, toolTip, glowOpacity);
        TrackGraphBounds(new Rect(x - captionWidth / 2, y - radius - 5, captionWidth, radius * 2 + 43));
    }
    private void TrackGraphBounds(Rect bounds)
    {
        if (_graphContentBounds.IsEmpty) _graphContentBounds = bounds;
        else _graphContentBounds.Union(bounds);
    }

    private static double GraphClusterRadius(int entryCount)
    {
        int remaining = entryCount, ring = 0;
        double radius = 58;
        while (remaining > 0)
        {
            radius = 82 + ring * 62;
            remaining -= Math.Max(6, (int)Math.Floor(Math.PI * 2 * radius / 82));
            ring++;
        }
        // Include the half-width of a site caption, not just its circle.
        return radius + 74;
    }

    private void ApplyGraphTransform()
    {
        GraphTransform.Matrix = new Matrix(_graphZoom, 0, 0, _graphZoom, _graphPan.X, _graphPan.Y);
        GraphZoomText.Text = $"{_graphZoom * 100:0}%";
    }

    private void FitGraphToViewport()
    {
        if (_graphContentBounds.IsEmpty || GraphViewport.ActualWidth <= 0) return;
        double availableWidth = Math.Max(1, GraphViewport.ActualWidth - 72);
        double availableHeight = Math.Max(1, GraphViewport.ActualHeight - 96);
        _graphZoom = Math.Clamp(Math.Min(availableWidth / _graphContentBounds.Width, availableHeight / _graphContentBounds.Height), .08, 1.2);
        _graphPan = new Vector(
            36 + (availableWidth - _graphContentBounds.Width * _graphZoom) / 2 - _graphContentBounds.X * _graphZoom,
            24 + (availableHeight - _graphContentBounds.Height * _graphZoom) / 2 - _graphContentBounds.Y * _graphZoom);
        _graphNeedsFit = false;
        ApplyGraphTransform();
    }

    private void ZoomGraphAt(double factor, Point anchor)
    {
        double next = Math.Clamp(_graphZoom * factor, .08, 2.5);
        if (Math.Abs(next - _graphZoom) < .001) return;
        Point world = new((anchor.X - _graphPan.X) / _graphZoom, (anchor.Y - _graphPan.Y) / _graphZoom);
        _graphZoom = next;
        _graphPan = new Vector(anchor.X - world.X * next, anchor.Y - world.Y * next);
        ConstrainGraphPan();
        _graphNeedsFit = false;
        ApplyGraphTransform();
    }

    private void ConstrainGraphPan()
    {
        if (_graphWorldWidth <= 0) return;
        const double visibleEdge = 90;
        double scaledWidth = _graphWorldWidth * _graphZoom;
        double scaledHeight = _graphWorldHeight * _graphZoom;
        double x = scaledWidth <= GraphViewport.ActualWidth
            ? (GraphViewport.ActualWidth - scaledWidth) / 2
            : Math.Clamp(_graphPan.X, GraphViewport.ActualWidth - visibleEdge - scaledWidth, visibleEdge);
        double y = scaledHeight <= GraphViewport.ActualHeight
            ? (GraphViewport.ActualHeight - scaledHeight) / 2
            : Math.Clamp(_graphPan.Y, GraphViewport.ActualHeight - visibleEdge - scaledHeight, visibleEdge);
        _graphPan = new Vector(x, y);
    }

    private static Color WithAlpha(Color color, byte alpha) => Color.FromArgb(alpha, color.R, color.G, color.B);

    private void GraphCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (GraphPage.Visibility != Visibility.Visible) return;
        RequestGraphUpdate();
    }

    private void RequestGraphUpdate()
    {
        if (_graphUpdateScheduled) return;
        _graphUpdateScheduled = true;
        Dispatcher.BeginInvoke(() =>
        {
            _graphUpdateScheduled = false;
            if (_vault is null || GraphPage.Visibility != Visibility.Visible) return;
            Size viewport = GraphViewport.RenderSize;
            if (viewport != _lastGraphViewportSize) _graphNeedsFit = true;
            if (_graphLayoutDirty) DrawGraph();
            else if (_graphNeedsFit) FitGraphToViewport();
            _lastGraphViewportSize = viewport;
        }, DispatcherPriority.Loaded);
    }
    private void GraphMinus_Click(object sender, RoutedEventArgs e) => ZoomGraphAt(1 / 1.18, new Point(GraphViewport.ActualWidth / 2, GraphViewport.ActualHeight / 2));
    private void GraphPlus_Click(object sender, RoutedEventArgs e) => ZoomGraphAt(1.18, new Point(GraphViewport.ActualWidth / 2, GraphViewport.ActualHeight / 2));
    private void GraphFit_Click(object sender, RoutedEventArgs e) => FitGraphToViewport();
    private void GraphViewport_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        ZoomGraphAt(e.Delta > 0 ? 1.14 : 1 / 1.14, e.GetPosition(GraphViewport));
        e.Handled = true;
    }
    private void GraphViewport_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            FitGraphToViewport();
            e.Handled = true;
            return;
        }
        _graphDragging = true;
        _graphDragStart = e.GetPosition(GraphViewport);
        _graphPanAtDragStart = _graphPan;
        EnableGraphInteractionCache();
        GraphViewport.CaptureMouse();
        GraphViewport.Cursor = Cursors.ScrollAll;
        e.Handled = true;
    }
    private void GraphViewport_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_graphDragging) return;
        if (e.LeftButton != MouseButtonState.Pressed) { EndGraphPan(); return; }
        Point current = e.GetPosition(GraphViewport);
        _graphPan = _graphPanAtDragStart + (current - _graphDragStart);
        ConstrainGraphPan();
        _graphNeedsFit = false;
        ApplyGraphTransform();
    }
    private void GraphViewport_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        EndGraphPan();
        e.Handled = true;
    }

    private void GraphViewport_LostMouseCapture(object sender, MouseEventArgs e) => EndGraphPan(releaseCapture: false);

    private void EnableGraphInteractionCache()
    {
        DpiScale dpi = VisualTreeHelper.GetDpi(GraphCanvas);
        GraphCanvas.CacheMode = new BitmapCache
        {
            EnableClearType = true,
            RenderAtScale = Math.Clamp(_graphZoom * dpi.DpiScaleX, .75, 2.5),
        };
    }

    private void EndGraphPan(bool releaseCapture = true)
    {
        if (!_graphDragging && GraphCanvas.CacheMode is null) return;
        _graphDragging = false;
        GraphCanvas.CacheMode = null;
        if (releaseCapture && GraphViewport.IsMouseCaptured) GraphViewport.ReleaseMouseCapture();
        GraphViewport.Cursor = Cursors.SizeAll;
        ApplyGraphTransform();
    }
    private async void ConfigureAppPassword_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AppPasswordSetupDialog(this, Settings.AppPasswordEnabled);
        if (ShowSecureDialog(dialog) != true) return;
        if (Settings.AppPasswordEnabled)
        {
            using SecureString current = dialog.TakeCurrentPassword();
            Mouse.OverrideCursor = Cursors.Wait;
            bool valid;
            try { valid = await _settingsService.VerifyAppPasswordAsync(current); }
            finally { Mouse.OverrideCursor = null; }
            if (!valid) { MessageBox.Show(this, "Текущий пароль приложения неверен.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        }
        if (dialog.RemoveRequested) _settingsService.RemoveAppPassword();
        else
        {
            using SecureString next = dialog.TakeNewPassword();
            Mouse.OverrideCursor = Cursors.Wait;
            try { await _settingsService.SetAppPasswordAsync(next); }
            finally { Mouse.OverrideCursor = null; }
        }
        RefreshSecurityControls();
    }

    private async void ToggleHello_Click(object sender, RoutedEventArgs e)
    {
        if (Settings.WindowsHelloEnabled)
        {
            if (_helloAvailable && !await WindowsHelloService.VerifyAsync(this, "Отключить Windows Hello в PersonGuard")) return;
            Settings.WindowsHelloEnabled = false; _settingsService.Save(); RefreshSecurityControls(); return;
        }
        if (!Settings.AppPasswordEnabled) { MessageBox.Show(this, "Сначала установите пароль приложения — он останется резервным способом входа.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        _helloAvailable = await WindowsHelloService.IsAvailableAsync();
        if (!_helloAvailable) { MessageBox.Show(this, "Windows Hello не настроен или недоступен на этом устройстве.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        if (!await WindowsHelloService.VerifyAsync(this, "Включить Windows Hello для PersonGuard")) return;
        Settings.WindowsHelloEnabled = true; _settingsService.Save(); RefreshSecurityControls();
    }

    private void SecuritySettingChanged(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;
        Settings.ScreenCaptureProtection = CaptureProtectionCheck.IsChecked == true;
        Settings.ClipboardEnabled = ClipboardCheck.IsChecked == true;
        Settings.LockOnFocusLoss = FocusLockCheck.IsChecked == true;
        _settingsService.Save();
        SyncVaultPolicy();
        if (!Settings.ClipboardEnabled) ClearOwnedClipboard();
        NativeSecurity.SetCaptureProtection(this, Settings.ScreenCaptureProtection);
    }

    private void AutoLockCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingSettings || AutoLockCombo.SelectedItem is not ComboBoxItem item || !int.TryParse(item.Tag?.ToString(), out int minutes)) return;
        Settings.AutoLockMinutes = minutes; _settingsService.Save(); SyncVaultPolicy(); _lastActivity = DateTimeOffset.UtcNow;
    }

    private void SyncVaultPolicy()
    {
        if (_vault is null) return;
        _vault.Policy = Settings.ToPolicy();
        SetDirty(true);
    }

    private async void ChangeMasterPassword_Click(object sender, RoutedEventArgs e)
    {
        // A Windows Hello PIN must not be enough to replace the master password.
        if (_session is null || !await ReauthenticateSecretAsync("Изменить мастер‑пароль", masterPasswordOnly: true)) return;
        if (_session is not { } session) return;
        int epoch = _securityEpoch;
        var dialog = new VaultCredentialsDialog(this, changePassword: true);
        if (ShowSecureDialog(dialog) != true) return;
        if (!IsCurrentSession(session, epoch)) return;
        using SecureString password = dialog.TakeMasterPassword();
        bool hadPasskey = session.Passkey is not null;
        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            await Task.Run(() => PgdCryptoService.ChangeMasterPassword(session, password));
            if (!IsCurrentSession(session, epoch)) return;
            MarkChanged();
            await SaveVaultAsync(false);
            if (hadPasskey)
                MessageBox.Show(this, "Ключ шифрования сейфа заменён, поэтому ключ входа отключён. При необходимости подключите его заново в разделе «Безопасность».", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { ShowSafeError("Не удалось изменить мастер‑пароль", ex); }
        finally { Mouse.OverrideCursor = null; RefreshSecurityControls(); }
    }

    private async Task<T> RunPasskeyAsync<T>(Func<nint, T> operation)
    {
        if (_passkeyBusy) throw new InvalidDataException("Дождитесь завершения операции ключа входа.");
        nint hwnd = new WindowInteropHelper(this).EnsureHandle();
        int epoch = _securityEpoch;
        _passkeyBusy = true;
        _suppressAutoLock = true;
        IsEnabled = false;
        Mouse.OverrideCursor = null;
        try
        {
            T result = await Task.Run(() => operation(hwnd));
            if (epoch != _securityEpoch)
            {
                if (result is byte[] secret) CryptographicOperations.ZeroMemory(secret);
                throw new InvalidDataException("Операция ключа входа прервана блокировкой Windows или сейфа.");
            }
            return result;
        }
        finally
        {
            IsEnabled = true;
            _passkeyBusy = false;
            _suppressAutoLock = false;
            _lastActivity = DateTimeOffset.UtcNow;
        }
    }

    private async void TogglePasskey_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || _passkeyBusy) return;
        // Managing alternate unlock methods always requires the recovery master password.
        var dialog = new PasswordDialog(this, "Настроить ключ входа", "Подтвердите резервный мастер-пароль этого сейфа.", "Мастер-пароль файла");
        if (ShowSecureDialog(dialog) != true) return;
        if (_session is null) return;
        using SecureString password = dialog.TakePassword();
        VaultSession session = _session;
        try
        {
            if (!PgdCryptoService.VerifyMasterPassword(session, password)) throw new CryptographicException("Неверный мастер-пароль.");
            PasskeyEnvelope? previous = session.Passkey;
            PasskeyEnvelope? replacement = null;
            if (previous is null)
            {
                MessageBox.Show(this, "В системном окне выберите iPhone/iPad или другой провайдер с PRF. Для iPhone могут потребоваться интернет и Bluetooth. После создания подтвердите ключ один раз для проверки разблокировки.\n\nСейф перейдёт в PGD3; старые версии PersonGuard не смогут его открыть. Мастер-пароль сохранится.", "Подключение ключа входа", MessageBoxButton.OK, MessageBoxImage.Information);
                byte[] id = await RunPasskeyAsync(PasskeyService.Register);
                byte[] salt = RandomNumberGenerator.GetBytes(32);
                byte[] prf = await RunPasskeyAsync(hwnd => PasskeyService.Evaluate(hwnd, id, salt));
                try
                {
                    if (_session != session) return;
                    replacement = PgdCryptoService.CreatePasskeyEnvelope(session, id, salt, prf);
                }
                finally { CryptographicOperations.ZeroMemory(prf); }
            }
            else
            {
                // Same password, new data key: the removed slot cannot open this or any later save.
                await Task.Run(() => PgdCryptoService.ChangeMasterPassword(session, password));
            }
            if (_session != session) return;
            session.Passkey = replacement;
            MarkChanged();
            bool saved = await SaveVaultAsync(false);
            if (_session != session) return;
            // A removal stays pending: restoring the old slot would wrap a key that no longer decrypts the vault.
            if (!saved && replacement is not null) { session.Passkey = null; MarkChanged(); }
            else MessageBox.Show(this, replacement is null
                ? "Ключ отключён для текущего файла. При необходимости удалите его из приложения «Пароли». Старые резервные копии PGD3 по-прежнему могут открываться этим ключом."
                : "Ключ подключён. На стартовом экране используйте «Открыть ключом входа». Сохраните мастер-пароль и резервную копию сейфа.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { ShowSafeError("Не удалось настроить ключ входа", ex); }
        finally { RefreshSecurityControls(); }
    }

    private void RefreshSecurityControls()
    {
        _loadingSettings = true;
        try
        {
            PasskeyStatusText.Text = _session?.Passkey is null ? "Не подключён · мастер-пароль остаётся резервным способом" : "Подключён к этому сейфу · формат PGD3";
            PasskeyButton.Content = _session?.Passkey is null ? "Подключить" : "Отключить";
            PasskeyButton.IsEnabled = _session is not null && !_passkeyBusy;
            AppPasswordStatus.Text = Settings.AppPasswordEnabled ? "Включён · Argon2id + DPAPI" : "Не настроен";
            HelloStatusText.Text = !_helloAvailable ? "Недоступен на этом устройстве" : Settings.WindowsHelloEnabled ? "Включён для входа и секретных действий" : "Доступен, но выключен";
            HelloButton.Content = Settings.WindowsHelloEnabled ? "Отключить" : "Включить";
            CaptureProtectionCheck.IsChecked = Settings.ScreenCaptureProtection;
            ClipboardCheck.IsChecked = Settings.ClipboardEnabled;
            FocusLockCheck.IsChecked = Settings.LockOnFocusLoss;
            foreach (ComboBoxItem item in AutoLockCombo.Items)
                if (item.Tag?.ToString() == Settings.AutoLockMinutes.ToString()) { AutoLockCombo.SelectedItem = item; break; }
        }
        finally { _loadingSettings = false; }
    }

    private async void LockVault_Click(object sender, RoutedEventArgs e) => await LockVaultAsync("Сейф заблокирован", automatic: false);
    private async Task LockVaultAsync(string reason, bool automatic)
    {
        if (_vault is null || _locking) return;
        _locking = true;
        _securityEpoch++;
        foreach (VaultEntry entry in _vault.Entries) entry.HidePassword();
        // Remove sensitive content immediately, before an asynchronous encrypted save.
        VaultView.Visibility = Visibility.Collapsed;
        try
        {
            if (_dirty && _filePath is not null)
            {
                if (!await SaveVaultAsync(false, reportErrors: !automatic) && !automatic) return;
            }
            else if (_dirty && _filePath is null && !automatic)
            {
                MessageBoxResult answer = MessageBox.Show(this, "Сейф ещё не сохранён. Заблокировать и удалить несохранённые данные из памяти?", "PersonGuard", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) return;
            }
            ClearVaultMemory();
            VaultView.Visibility = Visibility.Collapsed;
            _appUnlocked = !(Settings.AppPasswordEnabled || Settings.WindowsHelloEnabled);
            AppLockedView.Visibility = _appUnlocked ? Visibility.Collapsed : Visibility.Visible;
            WelcomeView.Visibility = _appUnlocked ? Visibility.Visible : Visibility.Collapsed;
            Title = "PersonGuard — " + reason;
        }
        finally
        {
            _locking = false;
            if (_vault is not null) VaultView.Visibility = Visibility.Visible;
        }
    }

    private void ClearVaultMemory()
    {
        _securityEpoch++;
        VaultDocument? vault = _vault;
        VaultSession? session = _session;
        _vault = null;
        _session = null;
        _filteredEntries.Clear(); _entryPageIndex = 0;
        _visibleEntries.Clear();
        _graphDrawing.Clear(); _lastGraphViewportSize = Size.Empty;
        foreach (DispatcherTimer timer in _revealTimers.Values) timer.Stop();
        _revealTimers.Clear();
        ClearOwnedClipboard();
        EntriesList.ItemsSource = null; GroupsList.ItemsSource = null; PasswordAlertsList.ItemsSource = null; GraphCanvas.Children.Clear();
        VaultNameText.Text = "Мои пароли"; FilePathText.Text = string.Empty; SearchBox.Text = string.Empty;
        _graphLayoutDirty = true; _graphNeedsFit = true; _graphWorldWidth = _graphWorldHeight = 0; _graphContentBounds = Rect.Empty;
        vault?.Dispose();
        session?.Dispose();
        _filePath = null; _dirty = false;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
    }

    private async void InactivityTimer_Tick(object? sender, EventArgs e)
    {
        if (_vault is null || Settings.AutoLockMinutes == 0 || _suppressAutoLock) return;
        if (DateTimeOffset.UtcNow - _lastActivity >= TimeSpan.FromMinutes(Settings.AutoLockMinutes)) await LockVaultAsync("Автоблокировка", automatic: true);
    }
    private void ActivityDetected(object sender, InputEventArgs e) => _lastActivity = DateTimeOffset.UtcNow;
    private async void Window_StateChanged(object? sender, EventArgs e)
    {
        UpdateWindowCorners();
        if (WindowState == WindowState.Minimized && !_suppressAutoLock)
            await LockVaultAsync("Блокировка при сворачивании", automatic: true);
    }

    private void UpdateWindowCorners()
    {
        bool rounded = WindowState != WindowState.Maximized;
        NativeSecurity.SetRoundedCorners(this, rounded);
        var chrome = System.Windows.Shell.WindowChrome.GetWindowChrome(this);
        // WindowChrome passes this value to CreateRoundRectRgn as the ellipse
        // diameter. A 24-DIP diameter matches the visible border's 12-DIP radius.
        if (chrome is not null) chrome.CornerRadius = new CornerRadius(rounded ? 24 : 0);
        WindowFrame.CornerRadius = new CornerRadius(rounded ? 12 : 0);
        UpdateWindowContentClip();
    }

    private void WindowContent_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateWindowContentClip();

    private void UpdateWindowContentClip()
    {
        if (WindowContent is null || WindowContent.ActualWidth <= 0 || WindowContent.ActualHeight <= 0) return;
        // One inner contour, inset by the one-DIP frame. Child backgrounds cannot
        // cover the curved border or leave a differently rounded title-bar seam.
        double radius = WindowState == WindowState.Maximized ? 0 : 11;
        var clip = new RectangleGeometry(new Rect(0, 0, WindowContent.ActualWidth, WindowContent.ActualHeight), radius, radius);
        clip.Freeze();
        WindowContent.Clip = clip;
    }
    private async void Window_Deactivated(object? sender, EventArgs e)
    {
        if (!Settings.LockOnFocusLoss || _suppressAutoLock || _vault is null) return;
        await Task.Delay(250);
        if (!IsActive && !_suppressAutoLock) await LockVaultAsync("Блокировка при смене окна", automatic: true);
    }
    private void SystemEvents_SessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            Dispatcher.BeginInvoke(async () =>
            {
                _securityEpoch++;
                foreach (SecureDialogBase dialog in OwnedWindows.OfType<SecureDialogBase>().ToArray()) dialog.Close();
                await LockVaultAsync("Windows заблокирован", automatic: true);
            });
    }

    private bool? ShowSecureDialog(SecureDialogBase dialog)
    {
        _suppressAutoLock = true;
        dialog.SourceInitialized += (_, _) => NativeSecurity.SetCaptureProtection(dialog, Settings.ScreenCaptureProtection);
        try { return dialog.ShowDialog(); }
        finally { _suppressAutoLock = false; _lastActivity = DateTimeOffset.UtcNow; }
    }

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_passkeyBusy) { e.Cancel = true; return; }
        if (_closingAfterSave) { ClearVaultMemory(); _inactivityTimer.Stop(); SystemEvents.SessionSwitch -= SystemEvents_SessionSwitch; return; }
        if (_vault is null || !_dirty) { ClearVaultMemory(); _inactivityTimer.Stop(); SystemEvents.SessionSwitch -= SystemEvents_SessionSwitch; return; }
        e.Cancel = true;
        MessageBoxResult result = MessageBox.Show(this, "Сохранить изменения перед закрытием?", "PersonGuard", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (result == MessageBoxResult.Cancel) return;
        if (result == MessageBoxResult.Yes && !await SaveVaultAsync(false)) return;
        _closingAfterSave = true;
        Close();
    }

    private static string EntryCountText(int count)
    {
        int mod10 = count % 10, mod100 = count % 100;
        if (mod10 == 1 && mod100 != 11) return $"{count} запись";
        if (mod10 is >= 2 and <= 4 && (mod100 < 12 || mod100 > 14)) return $"{count} записи";
        return $"{count} записей";
    }
    private static string SafeFileName(string value)
    {
        foreach (char c in System.IO.Path.GetInvalidFileNameChars()) value = value.Replace(c, '-');
        value = value.Trim(); return value.Length == 0 ? "person-guard" : value[..Math.Min(value.Length, 60)];
    }
    private void ShowSafeError(string title, Exception error)
    {
        string message = error is CryptographicException or InvalidDataException ? error.Message : "Операция не выполнена. Расшифрованные данные не записывались в журнал.";
        MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
