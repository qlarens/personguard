using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop.Dialogs;

public abstract class SecureDialogBase : Window
{
    protected readonly StackPanel Body = new() { Margin = new Thickness(26) };
    protected readonly TextBlock ErrorText = new() { Foreground = new SolidColorBrush(Color.FromRgb(255, 107, 130)), FontSize = 12, Margin = new Thickness(0, 10, 0, 0), TextWrapping = TextWrapping.Wrap };

    protected SecureDialogBase(Window owner, string eyebrow, string title, string description, double width = 470)
    {
        Owner = owner;
        Width = width;
        SizeToContent = SizeToContent.Height;
        MaxHeight = SystemParameters.WorkArea.Height - 60;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ShowInTaskbar = false;
        FontFamily = new FontFamily("Segoe UI Variable Text, Segoe UI");
        Foreground = Brushes.White;

        var border = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(17, 23, 34)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(43, 54, 74)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(16),
            Child = new ScrollViewer
            {
                Content = Body,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            },
        };
        Content = border;

        var header = new Grid();
        header.ColumnDefinitions.Add(new ColumnDefinition());
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var heading = new StackPanel();
        heading.Children.Add(new TextBlock { Text = eyebrow, Foreground = new SolidColorBrush(Color.FromRgb(120, 150, 255)), FontSize = 10, FontWeight = FontWeights.Bold });
        heading.Children.Add(new TextBlock { Text = title, FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"), FontSize = 23, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 7, 0, 0) });
        header.Children.Add(heading);
        var close = Button("×", false);
        close.Width = close.Height = 32;
        close.Padding = new Thickness(0);
        close.Click += (_, _) => { DialogResult = false; Close(); };
        Grid.SetColumn(close, 1);
        header.Children.Add(close);
        Body.Children.Add(header);
        Body.Children.Add(new TextBlock { Text = description, Foreground = new SolidColorBrush(Color.FromRgb(127, 138, 157)), FontSize = 13, TextWrapping = TextWrapping.Wrap, LineHeight = 21, Margin = new Thickness(0, 13, 0, 8) });
        PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape) { DialogResult = false; Close(); } };
    }

    protected static TextBlock Label(string text) => new() { Text = text, Foreground = new SolidColorBrush(Color.FromRgb(172, 181, 196)), FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 13, 0, 7) };
    protected static TextBox CreateTextInput(string text = "") => new() { Text = text, MinHeight = 42 };
    protected static PasswordBox PasswordInput() => new() { MinHeight = 42 };

    protected static Button Button(string content, bool primary)
    {
        var button = new Button { Content = content, MinHeight = 40, Padding = new Thickness(16, 8, 16, 8), Margin = new Thickness(7, 0, 0, 0) };
        button.Style = (Style)Application.Current.Resources[primary ? "PrimaryButton" : "GhostButton"];
        return button;
    }

    protected StackPanel Footer(params Button[] buttons)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 22, 0, 0) };
        foreach (Button button in buttons) panel.Children.Add(button);
        return panel;
    }
}

public sealed class VaultCredentialsDialog : SecureDialogBase
{
    private readonly TextBox? _name;
    private readonly PasswordBox _password = PasswordInput();
    private readonly PasswordBox _confirm = PasswordInput();

    public VaultCredentialsDialog(Window owner, bool changePassword = false)
        : base(owner,
              changePassword ? "НОВЫЙ МАСТЕР‑ПАРОЛЬ" : "НОВОЕ ХРАНИЛИЩЕ",
              changePassword ? "Изменить мастер‑пароль" : "Создать защищённый сейф",
              "Минимум 14 символов. Мастер‑пароль не сохраняется и не может быть восстановлен.")
    {
        if (!changePassword)
        {
            Body.Children.Add(Label("Название сейфа"));
            _name = CreateTextInput("Мои пароли");
            _name.MaxLength = 48;
            Body.Children.Add(_name);
        }
        Body.Children.Add(Label("Мастер‑пароль"));
        Body.Children.Add(_password);
        Body.Children.Add(Label("Повторите пароль"));
        Body.Children.Add(_confirm);
        Body.Children.Add(ErrorText);
        var cancel = Button("Отмена", false);
        var submit = Button(changePassword ? "Изменить" : "Создать PGD2", true);
        cancel.Click += (_, _) => { DialogResult = false; Close(); };
        submit.Click += Submit;
        Body.Children.Add(Footer(cancel, submit));
        Loaded += (_, _) => (_name as Control ?? _password).Focus();
    }

    public string VaultName => _name?.Text.Trim() ?? string.Empty;
    public SecureString TakeMasterPassword()
    {
        SecureString copy = _password.SecurePassword.Copy();
        _password.Clear();
        _confirm.Clear();
        return copy;
    }

    private void Submit(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = string.Empty;
        if (_name is not null && string.IsNullOrWhiteSpace(_name.Text)) { ErrorText.Text = "Введите название сейфа."; return; }
        if (_password.SecurePassword.Length < 14) { ErrorText.Text = "Используйте минимум 14 символов."; return; }
        if (!SecureStringUtil.FixedTimeEquals(_password.SecurePassword, _confirm.SecurePassword)) { ErrorText.Text = "Пароли не совпадают."; return; }
        DialogResult = true;
        Close();
    }
}

public sealed class PasswordDialog : SecureDialogBase
{
    private readonly PasswordBox _password = PasswordInput();
    public PasswordDialog(Window owner, string title, string description, string label = "Мастер‑пароль")
        : base(owner, "ПОВТОРНАЯ АВТОРИЗАЦИЯ", title, description, 440)
    {
        Body.Children.Add(Label(label));
        Body.Children.Add(_password);
        Body.Children.Add(ErrorText);
        var cancel = Button("Отмена", false);
        var submit = Button("Подтвердить", true);
        cancel.Click += (_, _) => { DialogResult = false; Close(); };
        submit.Click += (_, _) =>
        {
            if (_password.SecurePassword.Length == 0) { ErrorText.Text = "Введите пароль."; return; }
            DialogResult = true;
            Close();
        };
        Body.Children.Add(Footer(cancel, submit));
        Loaded += (_, _) => _password.Focus();
    }
    public SecureString TakePassword()
    {
        SecureString copy = _password.SecurePassword.Copy();
        _password.Clear();
        return copy;
    }
    public void ShowError(string text) { ErrorText.Text = text; _password.Clear(); _password.Focus(); }
}

public sealed class EntryDialog : SecureDialogBase
{
    private readonly TextBox _title;
    private readonly TextBox _url;
    private readonly TextBox _username;
    private readonly TextBlock _usernameLabel;
    private readonly TextBox _phone;
    private readonly PasswordBox _password = PasswordInput();
    private readonly TextBox _visiblePassword = CreateTextInput();
    private readonly CheckBox _showPassword = new() { Content = "Показать пароль", Margin = new Thickness(0, 9, 0, 0) };
    private readonly TextBlock _passwordLabel;
    private readonly StackPanel _passwordSection = new();
    private readonly ComboBox _authProvider = new() { MinHeight = 42 };
    private readonly TextBlock _authHint = new()
    {
        Foreground = new SolidColorBrush(Color.FromRgb(127, 138, 157)),
        FontSize = 11,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 7, 0, 0),
    };
    private readonly CheckBox _favorite;
    private readonly VaultEntry? _existing;
    private bool _syncingPassword;

    public EntryDialog(Window owner, VaultEntry? existing)
        : base(owner, "ЗАПИСЬ В СЕЙФЕ", existing is null ? "Добавить учётную запись" : "Изменить запись",
              "Выберите вход по паролю или через Apple, Google либо Microsoft.", 520)
    {
        _existing = existing;
        Body.Children.Add(Label("Название сайта"));
        _title = CreateTextInput(existing?.Title ?? string.Empty); _title.MaxLength = 80; Body.Children.Add(_title);
        Body.Children.Add(Label("Ссылка"));
        _url = CreateTextInput(existing?.Url ?? string.Empty); _url.MaxLength = 600; Body.Children.Add(_url);
        Body.Children.Add(Label("Способ входа"));
        _authProvider.Items.Add(ProviderItem("Пароль", LoginProvider.Password));
        _authProvider.Items.Add(ProviderItem("Вход через Apple", LoginProvider.Apple));
        _authProvider.Items.Add(ProviderItem("Вход через Google", LoginProvider.Google));
        _authProvider.Items.Add(ProviderItem("Вход через Microsoft", LoginProvider.Microsoft));
        _authProvider.SelectedIndex = ProviderIndex(existing?.AuthProvider);
        _authProvider.SelectionChanged += (_, _) => UpdateAuthFields();
        Body.Children.Add(_authProvider);
        Body.Children.Add(_authHint);
        var columns = new Grid();
        columns.ColumnDefinitions.Add(new ColumnDefinition()); columns.ColumnDefinitions.Add(new ColumnDefinition());
        var left = new StackPanel { Margin = new Thickness(0, 0, 7, 0) };
        _usernameLabel = Label("Username или email"); left.Children.Add(_usernameLabel); _username = CreateTextInput(existing?.Username ?? string.Empty); _username.MaxLength = 180; left.Children.Add(_username);
        var right = new StackPanel { Margin = new Thickness(7, 0, 0, 0) };
        right.Children.Add(Label("Телефон · необязательно")); _phone = CreateTextInput(existing?.Phone ?? string.Empty); _phone.MaxLength = 60; right.Children.Add(_phone);
        columns.Children.Add(left); Grid.SetColumn(right, 1); columns.Children.Add(right); Body.Children.Add(columns);
        _passwordLabel = Label(existing is null ? "Пароль" : "Новый пароль · необязательно");
        _passwordSection.Children.Add(_passwordLabel);
        var passwordInputs = new Grid();
        _password.MaxLength = 1000;
        _visiblePassword.MaxLength = 1000;
        _visiblePassword.Visibility = Visibility.Collapsed;
        _visiblePassword.TextChanged += (_, _) => SyncVisiblePassword();
        passwordInputs.Children.Add(_password);
        passwordInputs.Children.Add(_visiblePassword);
        _passwordSection.Children.Add(passwordInputs);
        _showPassword.Checked += (_, _) => SetPasswordVisibility(true);
        _showPassword.Unchecked += (_, _) => SetPasswordVisibility(false);
        _passwordSection.Children.Add(_showPassword);
        var generator = Button("Сгенерировать 28 символов", false); generator.HorizontalAlignment = HorizontalAlignment.Left; generator.Margin = new Thickness(0, 9, 0, 0);
        generator.Click += (_, _) => SetPassword(PasswordGenerator.Create(28));
        _passwordSection.Children.Add(generator);
        Body.Children.Add(_passwordSection);
        _phone.TextChanged += (_, _) => UpdateAuthFields(clearPassword: false);
        _favorite = new CheckBox { Content = "Добавить в избранное", IsChecked = existing?.Favorite ?? false, Margin = new Thickness(0, 16, 0, 0) };
        Body.Children.Add(_favorite); Body.Children.Add(ErrorText);
        var delete = Button("Удалить", false); delete.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 140)); delete.Visibility = existing is null ? Visibility.Collapsed : Visibility.Visible;
        var cancel = Button("Отмена", false); var save = Button("Сохранить запись", true);
        delete.Click += (_, _) => { if (MessageBox.Show(this, "Удалить запись? После сохранения файла действие нельзя отменить.", "PersonGuard", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { DeleteRequested = true; DialogResult = true; Close(); } };
        cancel.Click += (_, _) => { DialogResult = false; Close(); }; save.Click += Submit;
        var footer = Footer(delete, cancel, save); footer.HorizontalAlignment = HorizontalAlignment.Stretch; Body.Children.Add(footer);
        UpdateAuthFields(clearPassword: false);
        Loaded += (_, _) => _title.Focus();
    }

    public bool DeleteRequested { get; private set; }
    public string EntryTitle => _title.Text.Trim();
    public string Url => _url.Text.Trim();
    public string Username => _username.Text.Trim();
    public string Phone => _phone.Text.Trim();
    public bool Favorite => _favorite.IsChecked == true;
    public string AuthProvider => (_authProvider.SelectedItem as ComboBoxItem)?.Tag as string ?? LoginProvider.Password;
    public bool UsesPassword => AuthProvider == LoginProvider.Password;
    public bool HasNewPassword => UsesPassword && _password.SecurePassword.Length > 0;
    public SecureString TakeNewPassword()
    {
        SyncVisiblePassword();
        SecureString copy = _password.SecurePassword.Copy();
        ClearPasswordInputs();
        return copy;
    }

    private void Submit(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = string.Empty;
        if (EntryTitle.Length == 0) { ErrorText.Text = "Введите название записи."; return; }
        if (Username.Length == 0 && Phone.Length == 0) { ErrorText.Text = "Укажите username, email или номер телефона."; return; }
        if (!UsesPassword && !VaultEntry.IsEmail(Username)) { ErrorText.Text = "Для входа через сервис укажите корректный email, связанный с ключом входа."; return; }
        bool canKeepExistingPassword = _existing?.UsesPassword == true && UsesPassword;
        if (UsesPassword && !canKeepExistingPassword && _password.SecurePassword.Length == 0 && Phone.Length == 0) { ErrorText.Text = "Введите пароль или укажите номер телефона."; return; }
        if (Url.Length > 0 && NormalizeUrl(Url) is null) { ErrorText.Text = "Введите корректную http/https ссылку."; return; }
        DialogResult = true;
        Close();
    }

    private static ComboBoxItem ProviderItem(string title, string provider) => new() { Content = title, Tag = provider };

    private static int ProviderIndex(string? provider) => LoginProvider.Normalize(provider) switch
    {
        LoginProvider.Apple => 1,
        LoginProvider.Google => 2,
        LoginProvider.Microsoft => 3,
        _ => 0,
    };

    private void UpdateAuthFields(bool clearPassword = true)
    {
        bool usesPassword = UsesPassword;
        bool canKeepExistingPassword = _existing?.UsesPassword == true;
        _passwordSection.Visibility = usesPassword ? Visibility.Visible : Visibility.Collapsed;
        bool phoneMakesPasswordOptional = usesPassword && Phone.Length > 0;
        _passwordLabel.Text = canKeepExistingPassword
            ? "Новый пароль · необязательно"
            : phoneMakesPasswordOptional ? "Пароль · необязательно при наличии телефона" : "Пароль";
        _usernameLabel.Text = usesPassword ? "Username или email · либо телефон" : "Email, связанный с ключом входа";
        _authHint.Text = usesPassword
            ? canKeepExistingPassword
                ? "Оставьте поле пустым, чтобы сохранить прежний пароль."
                : phoneMakesPasswordOptional
                    ? "Номер телефона указан, поэтому запись можно сохранить без пароля."
                    : "Введите или сгенерируйте пароль. Если укажете телефон, пароль станет необязательным."
            : $"Пароль не нужен. Укажите почту iCloud, где хранится ключ входа через {LoginProvider.DisplayName(AuthProvider)} — запись останется в общей email‑группе.";
        if (!usesPassword && clearPassword) ClearPasswordInputs();
    }

    private void SetPasswordVisibility(bool visible)
    {
        if (_syncingPassword) return;
        _syncingPassword = true;
        try
        {
            if (visible)
            {
                _visiblePassword.Text = _password.Password;
                _password.Visibility = Visibility.Collapsed;
                _visiblePassword.Visibility = Visibility.Visible;
                _visiblePassword.Focus();
                _visiblePassword.CaretIndex = _visiblePassword.Text.Length;
            }
            else
            {
                _password.Password = _visiblePassword.Text;
                _visiblePassword.Clear();
                _visiblePassword.Visibility = Visibility.Collapsed;
                _password.Visibility = Visibility.Visible;
                _password.Focus();
            }
        }
        finally { _syncingPassword = false; }
    }

    private void SyncVisiblePassword()
    {
        if (_syncingPassword || _visiblePassword.Visibility != Visibility.Visible) return;
        _syncingPassword = true;
        try { _password.Password = _visiblePassword.Text; }
        finally { _syncingPassword = false; }
    }

    private void SetPassword(string value)
    {
        _syncingPassword = true;
        try
        {
            _password.Password = value;
            if (_visiblePassword.Visibility == Visibility.Visible)
            {
                _visiblePassword.Text = value;
                _visiblePassword.CaretIndex = value.Length;
            }
        }
        finally { _syncingPassword = false; }
    }

    private void ClearPasswordInputs()
    {
        _syncingPassword = true;
        try
        {
            _password.Clear();
            _visiblePassword.Clear();
            _visiblePassword.Visibility = Visibility.Collapsed;
            _password.Visibility = Visibility.Visible;
            _showPassword.IsChecked = false;
        }
        finally { _syncingPassword = false; }
    }

    public static string? NormalizeUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        string candidate = value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? value : "https://" + value;
        return Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) ? uri.AbsoluteUri : null;
    }
}

public sealed class AppPasswordSetupDialog : SecureDialogBase
{
    private readonly PasswordBox _current = PasswordInput();
    private readonly PasswordBox _new = PasswordInput();
    private readonly PasswordBox _confirm = PasswordInput();
    private readonly bool _hasExisting;

    public AppPasswordSetupDialog(Window owner, bool hasExisting)
        : base(owner, "ЛОКАЛЬНАЯ ЗАЩИТА", "Пароль приложения", "Защищает запуск PersonGuard на этом пользователе Windows. Хеш и настройки дополнительно защищены DPAPI.")
    {
        _hasExisting = hasExisting;
        if (hasExisting) { Body.Children.Add(Label("Текущий пароль")); Body.Children.Add(_current); }
        Body.Children.Add(Label("Новый пароль")); Body.Children.Add(_new);
        Body.Children.Add(Label("Повторите новый пароль")); Body.Children.Add(_confirm);
        Body.Children.Add(ErrorText);
        var remove = Button("Удалить защиту", false); remove.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 140)); remove.Visibility = hasExisting ? Visibility.Visible : Visibility.Collapsed;
        var cancel = Button("Отмена", false); var save = Button("Сохранить", true);
        remove.Click += (_, _) =>
        {
            if (_current.SecurePassword.Length == 0) { ErrorText.Text = "Введите текущий пароль для удаления защиты."; return; }
            RemoveRequested = true; DialogResult = true; Close();
        };
        cancel.Click += (_, _) => { DialogResult = false; Close(); }; save.Click += Submit;
        Body.Children.Add(Footer(remove, cancel, save));
    }

    public bool RemoveRequested { get; private set; }
    public SecureString TakeCurrentPassword()
    {
        SecureString copy = _current.SecurePassword.Copy();
        _current.Clear();
        return copy;
    }
    public SecureString TakeNewPassword()
    {
        SecureString copy = _new.SecurePassword.Copy();
        _new.Clear();
        _confirm.Clear();
        return copy;
    }

    private void Submit(object sender, RoutedEventArgs e)
    {
        if (_hasExisting && _current.SecurePassword.Length == 0) { ErrorText.Text = "Введите текущий пароль."; return; }
        if (_new.SecurePassword.Length < 10) { ErrorText.Text = "Используйте минимум 10 символов."; return; }
        if (!SecureStringUtil.FixedTimeEquals(_new.SecurePassword, _confirm.SecurePassword)) { ErrorText.Text = "Новые пароли не совпадают."; return; }
        DialogResult = true; Close();
    }
}

public static class PasswordGenerator
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%&*+-_=?:";

    public static string Create(int length)
    {
        string all = Upper + Lower + Digits + Symbols;
        var chars = new List<char> { Pick(Upper), Pick(Lower), Pick(Digits), Pick(Symbols) };
        while (chars.Count < length) chars.Add(Pick(all));
        for (int i = chars.Count - 1; i > 0; i--)
        {
            int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string([.. chars]);
    }
    private static char Pick(string source) => source[System.Security.Cryptography.RandomNumberGenerator.GetInt32(source.Length)];
}
