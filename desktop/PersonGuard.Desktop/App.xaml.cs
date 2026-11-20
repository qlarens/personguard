using System.Threading;
using System.Windows;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop;

public partial class App : Application
{
    private Mutex? _singleInstance;
    private bool _ownsMutex;

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

        _singleInstance = new Mutex(true, "Local\\PersonGuard.Desktop.Singleton", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("PersonGuard уже запущен.", "PersonGuard", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }
        _ownsMutex = true;

        try
        {
            MainWindow = new MainWindow();
            MainWindow.Show();
        }
        catch (InvalidDataException error)
        {
            MessageBox.Show(error.Message, "PersonGuard — настройки защиты недоступны", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex) _singleInstance?.ReleaseMutex();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }
}
