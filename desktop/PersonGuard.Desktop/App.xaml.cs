using System.Threading;
using System.Windows;
using PersonGuard.Desktop.Installation;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop;

public partial class App : Application
{
    private Mutex? _singleInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        NativeSecurity.HardenProcess();
        base.OnStartup(e);

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            // Never serialize exception state or vault contents into application logs.
            if (args.IsTerminating)
                Current.Dispatcher.Invoke(() => MessageBox.Show("PersonGuard завершил работу из-за внутренней ошибки. Сейф удалён из памяти.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Error));
        };

        if (InstallerService.IsUninstallRequest(e.Args, out bool quiet))
        {
            UninstallResult result = InstallerService.Uninstall(quiet);
            if (!quiet && result.Outcome != UninstallOutcome.Canceled)
            {
                MessageBox.Show(
                    result.Message,
                    "Удаление PersonGuard",
                    MessageBoxButton.OK,
                    result.Outcome == UninstallOutcome.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
            }

            Shutdown(result.Outcome == UninstallOutcome.Failure ? 1 : 0);
            return;
        }

        if (InstallerService.IsSetupRequest(e.Args))
        {
            MainWindow = new InstallerWindow();
            MainWindow.Show();
            return;
        }

        _singleInstance = new Mutex(true, "Local\\PersonGuard.Desktop.Singleton", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("PersonGuard уже запущен.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        MainWindow = new MainWindow();
        MainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _singleInstance?.ReleaseMutex();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }
}
