using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using PersonGuard.Desktop;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;

internal static class UiPerformanceProbe
{
    public static void Run(string[] args)
    {
        int count = args.Select(value => int.TryParse(value, out int number) ? number : 0).FirstOrDefault(value => value > 0);
        count = Math.Clamp(count == 0 ? 300 : count, 10, 2000);
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            string directory = Path.Combine(Path.GetTempPath(), "PersonGuard.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var app = new TestApp();
                app.InitializeComponent();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Console.WriteLine("[probe] opening synthetic window");
                var window = new MainWindow(new AppSettingsService(Path.Combine(directory, "security.pgcfg"))) { Width = 1250, Height = 820 };
                window.Show();
                Console.WriteLine("[probe] window shown");
                Pump();
                Console.WriteLine("[probe] initial layout settled");
                using var password = new SecureString();
                foreach (char value in "Synthetic benchmark master 2026!") password.AppendChar(value);
                password.MakeReadOnly();
                var vault = new VaultDocument { Name = "Synthetic performance fixture" };
                for (int index = 0; index < count; index++)
                    vault.Entries.Add(new VaultEntry
                    {
                        Title = $"Account {index:0000}", Url = $"https://account-{index}.example.test/login",
                        Username = $"profile-{index % 10}@example.test", Strength = 4,
                        Password = ProtectedSecret.FromString($"Benchmark-only-secret-{index:0000}!"),
                    });
                VaultSession session = PgdCryptoService.CreateSession(password);
                Console.WriteLine("[probe] synthetic vault prepared");
                var results = new Dictionary<string, object> { ["entries"] = count, ["samples"] = 7, ["metric"] = "UI thread through layout/dispatcher idle; milliseconds" };
                results["open_vault_ms"] = Measure(() => Invoke("ReplaceOpenVault", vault, session, null, false));
                Console.WriteLine("[probe] vault opened");
                var search = (TextBox)window.FindName("SearchBox");
                var header = search.TransformToAncestor(window).TransformBounds(new Rect(search.RenderSize));
                var region = (FrameworkElement)window.FindName("SearchRegion");
                results["search_height"] = new { control = search.ActualHeight, region = region.ActualHeight, top = header.Top, bottom = header.Bottom };
                results["first_graph_ms"] = Measure(() => Invoke("ShowGraphPage"));
                results["first_security_ms"] = Measure(() => Invoke("ShowSecurityPage"));
                Invoke("ShowVaultPage"); Pump();
                var samples = new Dictionary<string, List<double>>();
                for (int iteration = 0; iteration < 7; iteration++)
                {
                    Sample("graph_ms", () => Invoke("ShowGraphPage"));
                    Sample("security_ms", () => Invoke("ShowSecurityPage"));
                    Sample("vault_ms", () => Invoke("ShowVaultPage"));
                    Sample("search_ms", () => search.Text = iteration % 2 == 0 ? "Account 00" : "Account");
                    Sample("favorite_ms", () => Invoke("Favorite_Click", new Button { Tag = vault.Entries[0] }, new RoutedEventArgs()));
                }
                for (int iteration = 0; iteration < 7; iteration++)
                    Sample("search_page_changed_ms", () => search.Text = iteration % 2 == 0 ? "Account 01" : "Account 00");
                foreach (var (name, timings) in samples)
                {
                    double[] sorted = timings.Order().ToArray();
                    results[name] = new { median = sorted[sorted.Length / 2], min = sorted[0], max = sorted[^1] };
                }
                Console.WriteLine(JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
                Invoke("ClearVaultMemory");
                window.Close();
                app.Shutdown();
                if (args.Contains("--verify-budget"))
                {
                    foreach (string name in new[] { "graph_ms", "security_ms", "vault_ms" })
                        if (samples[name].Order().ElementAt(3) > 100)
                            throw new InvalidOperationException($"Warm tab performance exceeded the 100 ms median budget: {name}.");
                    if (samples["search_page_changed_ms"].Order().ElementAt(3) > 150)
                        throw new InvalidOperationException("Replacing a search result page exceeded the 150 ms median budget.");
                    Console.WriteLine("[PASS] warm tab median budget <= 100 ms");
                    Console.WriteLine("[PASS] search result page median budget <= 150 ms");
                }

                void Invoke(string name, params object?[] values) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, values);
                void Pump() { window.UpdateLayout(); window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle); window.UpdateLayout(); }
                double Measure(Action action) { var timer = Stopwatch.StartNew(); action(); Pump(); return Math.Round(timer.Elapsed.TotalMilliseconds, 2); }
                void Sample(string name, Action action) { if (!samples.TryGetValue(name, out var values)) samples[name] = values = []; values.Add(Measure(action)); }
            }
            catch (Exception error) { failure = error; }
            finally { Directory.Delete(directory, true); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw new InvalidOperationException("UI performance probe failed.", failure);
    }
}
