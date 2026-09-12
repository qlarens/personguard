using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Globalization;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop.Models;

public sealed class VaultDocument : IDisposable
{
    public int SchemaVersion { get; set; } = 2;
    public string VaultId { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Мои пароли";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public ObservableCollection<VaultEntry> Entries { get; } = [];

    public void Dispose()
    {
        foreach (VaultEntry entry in Entries) entry.Dispose();
        Entries.Clear();
    }
}

public sealed class VaultEntry : INotifyPropertyChanged, IDisposable
{
    private bool _favorite;
    private string _passwordDisplay = "••••••••••••";
    private string _passwordReuseWarning = string.Empty;
    private int _passwordReuseCount;
    private string _authProvider = LoginProvider.Password;
    private ProtectedSecret? _password;
    private bool _hasPassword;

    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Phone { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int Strength { get; set; }

    public string AuthProvider
    {
        get => _authProvider;
        set
        {
            string normalized = LoginProvider.Normalize(value);
            if (_authProvider == normalized) return;
            _authProvider = normalized;
            HidePassword();
            OnPropertyChanged();
            OnPropertyChanged(nameof(UsesPassword));
            OnPropertyChanged(nameof(SignInSummary));
            OnPropertyChanged(nameof(StrengthLabel));
            OnPropertyChanged(nameof(SecurityAccent));
            OnPropertyChanged(nameof(RiskBackground));
            OnPropertyChanged(nameof(RiskGlowOpacity));
        }
    }

    public bool Favorite
    {
        get => _favorite;
        set { if (_favorite == value) return; _favorite = value; OnPropertyChanged(); OnPropertyChanged(nameof(FavoriteGlyph)); }
    }

    public ProtectedSecret Password
    {
        get => _password ?? throw new ObjectDisposedException(nameof(VaultEntry));
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _password?.Dispose();
            _password = value;
            byte[] plaintext = value.RevealUtf8();
            try { _hasPassword = plaintext.Length > 0; }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
            OnPropertyChanged(nameof(HasPassword));
            OnPropertyChanged(nameof(UsesPassword));
            OnPropertyChanged(nameof(SignInSummary));
            OnPropertyChanged(nameof(StrengthLabel));
            OnPropertyChanged(nameof(SecurityAccent));
            OnPropertyChanged(nameof(RiskBackground));
            OnPropertyChanged(nameof(RiskGlowOpacity));
        }
    }

    public string PasswordDisplay
    {
        get => _passwordDisplay;
        set { _passwordDisplay = value; OnPropertyChanged(); OnPropertyChanged(nameof(SignInSummary)); }
    }

    public string FavoriteGlyph => Favorite ? "★" : "☆";
    public string SiteInitials => string.IsNullOrWhiteSpace(Title) ? "?" : string.Concat(Title.Trim().Take(2)).ToUpperInvariant();
    public string Host
    {
        get
        {
            if (!Uri.TryCreate(Url, UriKind.Absolute, out Uri? uri)) return "Без ссылки";
            return uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? uri.Host[4..] : uri.Host;
        }
    }
    public bool HasUrl => Uri.TryCreate(Url, UriKind.Absolute, out Uri? uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
    public string EmailGroup => IsEmail(Username) ? Username.Trim().ToLowerInvariant() : "Без email‑группы";
    public bool HasPassword => _hasPassword;
    public bool UsesPassword => AuthProvider == LoginProvider.Password && HasPassword;
    public int PasswordReuseCount => _passwordReuseCount;
    public bool HasReusedPassword => PasswordReuseCount > 1;
    public double PasswordReuseRisk => PasswordRiskPalette.RiskForReuseCount(PasswordReuseCount);
    public string PasswordReuseWarning => _passwordReuseWarning;
    internal void SetPasswordReuseStatus(int count, string warning)
    {
        count = Math.Max(UsesPassword ? 1 : 0, count);
        if (_passwordReuseCount == count && _passwordReuseWarning == warning) return;
        _passwordReuseCount = count;
        _passwordReuseWarning = warning;
        OnPropertyChanged(nameof(PasswordReuseCount));
        OnPropertyChanged(nameof(PasswordReuseRisk));
        OnPropertyChanged(nameof(PasswordReuseWarning));
        OnPropertyChanged(nameof(HasReusedPassword));
        OnPropertyChanged(nameof(StrengthLabel));
        OnPropertyChanged(nameof(SecurityAccent));
        OnPropertyChanged(nameof(RiskBackground));
        OnPropertyChanged(nameof(RiskGlowOpacity));
    }
    public string SignInSummary => UsesPassword
        ? PasswordDisplay
        : AuthProvider == LoginProvider.Password && !string.IsNullOrWhiteSpace(Phone)
            ? "Без пароля · вход по телефону"
            : $"Без пароля · вход через {LoginProvider.DisplayName(AuthProvider)}";
    public string StrengthLabel => HasReusedPassword
        ? PasswordReuseCount switch
        {
            2 => "ВНИМАНИЕ · ПАРОЛЬ В 2 ЗАПИСЯХ",
            3 => "ВЫСОКИЙ РИСК · ПАРОЛЬ В 3 ЗАПИСЯХ",
            _ => $"ОПАСНО · ПАРОЛЬ В {PasswordReuseCount} ЗАПИСЯХ",
        }
        : UsesPassword
            ? (Strength >= 3 ? "НАДЁЖНЫЙ" : "ПРОВЕРИТЬ")
            : AuthProvider == LoginProvider.Password
                ? "ВХОД ПО ТЕЛЕФОНУ"
                : $"ВХОД ЧЕРЕЗ {LoginProvider.DisplayName(AuthProvider).ToUpperInvariant()}";
    private double DisplayRisk => HasReusedPassword ? PasswordReuseRisk : UsesPassword && Strength < 3 ? .5 : 0;
    public string SecurityAccent => PasswordRiskPalette.AccentHex(DisplayRisk);
    public string RiskBackground => PasswordRiskPalette.BackgroundHex(DisplayRisk);
    public double RiskGlowOpacity => .07 + DisplayRisk * .23;

    public void HidePassword() => PasswordDisplay = "••••••••••••";

    public static bool IsEmail(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        int at = value.IndexOf('@');
        return at > 0 && at == value.LastIndexOf('@') && at < value.Length - 3 && value.IndexOf('.', at) > at + 1;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void Dispose()
    {
        HidePassword();
        _password?.Dispose();
        _password = null;
        _hasPassword = false;
        _passwordReuseCount = 0;
        _passwordReuseWarning = string.Empty;
        Title = Url = Username = Phone = string.Empty;
    }
}

public static class LoginProvider
{
    public const string Password = "password";
    public const string Apple = "apple";
    public const string Google = "google";
    public const string Microsoft = "microsoft";

    public static string Normalize(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        Apple => Apple,
        Google => Google,
        Microsoft => Microsoft,
        _ => Password,
    };

    public static string DisplayName(string? value) => Normalize(value) switch
    {
        Apple => "Apple",
        Google => "Google",
        Microsoft => "Microsoft",
        _ => "паролю",
    };
}

public sealed record EmailGroup(string Email, int Count, string Initial);

public sealed record PasswordReuseAlert(IReadOnlyList<VaultEntry> Entries)
{
    public string EntryList => string.Join(", ", Entries.Select(EntryIdentity));
    public string Message => $"Один пароль используется в {Entries.Count} записях: {EntryList}. Смените его на уникальный в каждой записи.";
    public string RiskAccent => PasswordRiskPalette.AccentHex(PasswordRiskPalette.RiskForReuseCount(Entries.Count));
    public string RiskBackground => PasswordRiskPalette.BackgroundHex(PasswordRiskPalette.RiskForReuseCount(Entries.Count));

    private static string EntryIdentity(VaultEntry entry)
    {
        string login = !string.IsNullOrWhiteSpace(entry.Username) ? entry.Username : entry.Phone;
        return string.IsNullOrWhiteSpace(login) ? entry.Title : $"{entry.Title} ({login})";
    }
}

public static class PasswordRiskPalette
{
    private static readonly Color Safe = Color.FromRgb(87, 214, 154);
    private static readonly Color Caution = Color.FromRgb(227, 197, 87);
    private static readonly Color High = Color.FromRgb(243, 154, 75);
    private static readonly Color Danger = Color.FromRgb(255, 92, 114);
    private static readonly Color Surface = Color.FromRgb(15, 21, 31);

    public static double RiskForReuseCount(int count) => count switch
    {
        <= 1 => 0,
        2 => .5,
        3 => .75,
        _ => 1,
    };

    public static Color AccentColor(double risk)
    {
        risk = Math.Clamp(risk, 0, 1);
        return risk <= .5
            ? Lerp(Safe, Caution, risk / .5)
            : risk <= .75
                ? Lerp(Caution, High, (risk - .5) / .25)
                : Lerp(High, Danger, (risk - .75) / .25);
    }

    public static string AccentHex(double risk) => ToHex(AccentColor(risk));
    public static Color BackgroundColor(double risk) => Lerp(Surface, AccentColor(risk), .08 + Math.Clamp(risk, 0, 1) * .10);
    public static string BackgroundHex(double risk) => ToHex(BackgroundColor(risk));

    private static Color Lerp(Color from, Color to, double amount) => Color.FromRgb(
        (byte)Math.Round(from.R + (to.R - from.R) * amount),
        (byte)Math.Round(from.G + (to.G - from.G) * amount),
        (byte)Math.Round(from.B + (to.B - from.B) * amount));

    private static string ToHex(Color color) => $"#{color.R:X2}{color.G:X2}{color.B:X2}";
}

public sealed class NonEmptyStringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is string text && !string.IsNullOrWhiteSpace(text) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
