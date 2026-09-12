using System.ComponentModel;
using System.Windows;

namespace PersonGuard.Desktop.Installation;

public partial class InstallerWindow : Window
{
    private bool _isInstalling;

    public InstallerWindow()
    {
        InitializeComponent();
        LicenseTextBox.Text = LicenseInfo.Text;
        InstallPathText.Text = $"Версия {InstallerService.Version} · установка для текущего пользователя · {InstallerService.InstallDirectory}";
        if (InstallerService.IsInstalled)
        {
            HeadingText.Text = "Обновление PersonGuard";
            InstallButton.Content = "Обновить";
        }
    }

    private void AcceptLicense_Changed(object sender, RoutedEventArgs e)
    {
        InstallButton.IsEnabled = AcceptLicenseCheckBox.IsChecked == true && !_isInstalling;
        StatusText.Text = AcceptLicenseCheckBox.IsChecked == true
            ? "Всё готово к установке."
            : "Для установки примите условия лицензии.";
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (AcceptLicenseCheckBox.IsChecked != true || _isInstalling)
            return;

        _isInstalling = true;
        InstallButton.IsEnabled = false;
        CancelButton.IsEnabled = false;
        AcceptLicenseCheckBox.IsEnabled = false;
        DesktopShortcutCheckBox.IsEnabled = false;
        LaunchCheckBox.IsEnabled = false;
        InstallProgress.Visibility = Visibility.Visible;
        StatusText.Text = InstallerService.IsInstalled ? "Обновление файлов…" : "Установка файлов…";

        try
        {
            InstallResult result = await Task.Run(() => InstallerService.Install(DesktopShortcutCheckBox.IsChecked == true));
            StatusText.Text = result.WasUpdate ? "PersonGuard успешно обновлён." : "PersonGuard успешно установлен.";
            InstallProgress.Visibility = Visibility.Collapsed;

            bool launch = LaunchCheckBox.IsChecked == true;
            _isInstalling = false;
            if (launch)
                InstallerService.LaunchInstalledApplication();
            Close();
        }
        catch (Exception ex)
        {
            _isInstalling = false;
            InstallProgress.Visibility = Visibility.Collapsed;
            StatusText.Text = "Установка не завершена.";
            InstallButton.IsEnabled = true;
            CancelButton.IsEnabled = true;
            AcceptLicenseCheckBox.IsEnabled = true;
            DesktopShortcutCheckBox.IsEnabled = true;
            LaunchCheckBox.IsEnabled = true;
            MessageBox.Show(ex.Message, "Установка PersonGuard", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_isInstalling)
            e.Cancel = true;
    }
}
