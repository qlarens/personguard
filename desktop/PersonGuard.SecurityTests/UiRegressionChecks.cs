using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shell;
using System.Windows.Threading;
using PersonGuard.Desktop;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;

internal static class UiRegressionChecks
{
    public static void Run(MainWindow window, VaultDocument vault, string artifacts)
    {
        var family = (FontFamily)window.FindResource("AppFont");
        if (family.BaseUri is not null)
        {
            foreach (FontWeight weight in new[] { FontWeights.Light, FontWeights.Normal, FontWeights.SemiBold, FontWeights.Bold })
            {
                var face = new Typeface(family, FontStyles.Normal, weight, FontStretches.Normal);
                Check(face.TryGetGlyphTypeface(out GlyphTypeface glyph) && glyph.FamilyNames.Values.Contains("Manrope")
                    && glyph.Weight == weight && glyph.CharacterToGlyphMap.ContainsKey(0x0416)
                    && glyph.FontUri.Scheme == "pack", "Embedded Manrope face or Cyrillic was replaced by a fallback.");
            }
        }
        var search = (TextBox)window.FindName("SearchBox");
        var items = (ItemsControl)window.FindName("EntriesList");
        search.Text = "Manrope поиск 123"; Pump();
        Rect caret = search.GetRectFromCharacterIndex(0);
        Check(caret.Left >= 39 && caret.Left <= 43, $"Search text has doubled or missing padding: {caret.Left}.");
        Check(caret.Height >= 14 && caret.Top >= 0 && caret.Bottom <= search.ActualHeight, "Search text is vertically clipped.");
        Check(((FrameworkElement)window.FindName("SearchPlaceholder")).Visibility == Visibility.Collapsed, "Search placeholder overlaps entered text.");
        SaveElement(search, Path.Combine(artifacts, "ui-search-filled-preview.png"));
        search.Clear(); Pump();
        Check(((FrameworkElement)window.FindName("SearchPlaceholder")).Visibility == Visibility.Visible, "Empty search has no placeholder.");
        foreach (int width in new[] { 980, 1250 })
        {
            window.Width = width; Pump();
            var header = (FrameworkElement)window.FindName("ContentHeaderBorder");
            Rect input = search.TransformToAncestor(header).TransformBounds(new Rect(search.RenderSize));
            Check(input.Bottom <= header.ActualHeight - 12, "Search field is clipped by the header.");
            Check(((FrameworkElement)window.FindName("SearchRegion")).ActualHeight >= search.ActualHeight, "Search row is shorter than the input.");
            foreach (var footer in Descendants<StackPanel>(items).Where(element => element.Name == "EntryFooter"))
            {
                var badge = Descendants<Border>(footer).Single(element => element.Name == "EntryGroupBadge");
                var label = Descendants<TextBlock>(footer).Single(element => element.Name == "EntryRiskLabel");
                Rect badgeBounds = badge.TransformToAncestor(footer).TransformBounds(new Rect(badge.RenderSize));
                Rect labelBounds = label.TransformToAncestor(footer).TransformBounds(new Rect(label.RenderSize));
                Check(labelBounds.Top >= badgeBounds.Bottom + 5, "Email and risk label overlap.");
                Check(labelBounds.Right <= footer.ActualWidth + 1, "Risk label overflows the card.");
            }
            Button noLink = Descendants<Button>(items).First(button => button.Name == "SiteLink" && !button.IsEnabled);
            noLink.ApplyTemplate();
            var linkBorder = (Border)noLink.Template.FindName("LinkBorder", noLink);
            Check(linkBorder.Background is SolidColorBrush { Color.A: 0 }, "Disabled site link uses a light system background.");
            if (width == 980)
            {
                var card = Descendants<Border>(items).First(border => border.DataContext == noLink.DataContext && border.Style == window.FindResource("Card"));
                SaveElement(card, Path.Combine(artifacts, "ui-entry-card-preview.png"));
            }
        }

        Check(!Descendants<TextBlock>(window).Any(text => text.Text == "ЛОКАЛЬНО"), "Removed title-bar badge is still present.");
        Check(WindowChrome.GetWindowChrome(window).CornerRadius.TopLeft > 0, "Normal window has square corners.");
        CheckNativeCorners(window);
        CheckContentClip(window, 11);
        Check(!window.AllowsTransparency, "Rounded corners enabled the layered transparency window path.");
        window.WindowState = WindowState.Maximized; Pump();
        Check(WindowChrome.GetWindowChrome(window).CornerRadius.TopLeft == 0, "Maximized window retained rounded gaps.");
        CheckContentClip(window, 0);
        window.WindowState = WindowState.Normal; window.Width = 1250; window.Height = 760; Pump();
        Check(WindowChrome.GetWindowChrome(window).CornerRadius.TopLeft > 0, "Restoring the window did not restore rounded corners.");
        CheckNativeCorners(window);
        CheckContentClip(window, 11);

        var additions = new List<VaultEntry>();
        for (int index = 0; index < 60; index++)
        {
            var entry = new VaultEntry
            {
                Title = index == 59 ? "Unique pagination result" : $"Pagination {index:00}",
                Username = "pagination@example.test", Password = ProtectedSecret.FromString($"Synthetic-only-{index}!"), Strength = 4,
            };
            additions.Add(entry); vault.Entries.Add(entry);
        }
        Invoke("RefreshVaultUi"); Pump();
        Check(items.Items.Count == 24, "Large vault instantiated more than one page of cards.");
        var scroll = (ScrollViewer)window.FindName("EntriesPage");
        scroll.ScrollToVerticalOffset(180); Pump();
        double offset = scroll.VerticalOffset;
        Check(offset > 0, "Pagination fixture has no scrollable content.");
        object? first = items.Items[0];
        Invoke("NextEntries_Click", window, new RoutedEventArgs()); Pump();
        Check(items.Items.Count == 24 && !ReferenceEquals(items.Items[0], first), "Next page did not display the following entries.");
        Check(Math.Abs(scroll.VerticalOffset - offset) < 1, "Next page moved the scroll position.");
        Invoke("PreviousEntries_Click", window, new RoutedEventArgs()); Pump();
        Check(Math.Abs(scroll.VerticalOffset - offset) < 1, "Previous page moved the scroll position.");
        foreach (Button button in Descendants<Button>(window))
        {
            bool left = button.Style == window.FindResource("NavButton") || button.Style == window.FindResource("LinkButton")
                || button.Height == 68;
            Check(button.HorizontalContentAlignment == (left ? HorizontalAlignment.Left : HorizontalAlignment.Center)
                && button.VerticalContentAlignment == VerticalAlignment.Center, $"Button content has incorrect alignment: {button.Content}.");
        }
        Invoke("ShowGraphPage"); Pump();
        var graph = ((Canvas)window.FindName("GraphCanvas")).Children.OfType<PersonGuard.Desktop.Presentation.GraphDrawingSurface>().Single();
        Rect vaultBounds = graph.NodeBounds[^1];
        Check(!graph.NodeBounds.Take(graph.NodeBounds.Count - 1).Any(bounds => bounds.IntersectsWith(vaultBounds)),
            "Dense entry clusters overlap the vault node or its caption.");
        SaveElement((FrameworkElement)window.FindName("GraphViewport"), Path.Combine(artifacts, "ui-graph-dense-preview.png"));
        Invoke("ShowVaultPage"); Pump();
        search.Text = "Unique pagination result"; Pump();
        Check(items.Items.Count == 1 && ((VaultEntry)items.Items[0]).Title == "Unique pagination result", "Search skipped records outside the rendered page.");
        search.Text = "Pagination"; Pump();
        object? firstPage = items.ItemsSource;
        Border firstCard = Descendants<Border>(items).First(border => border.Style == window.FindResource("Card"));
        search.Text = "Pagin"; Pump();
        Check(ReferenceEquals(firstPage, items.ItemsSource), "Unchanged result page was unnecessarily rebuilt.");
        Check(ReferenceEquals(firstCard, Descendants<Border>(items).First(border => border.Style == window.FindResource("Card"))), "Typing a prefix recreated an unchanged card.");
        search.Clear(); Pump();
        foreach (VaultEntry entry in additions) { vault.Entries.Remove(entry); entry.Dispose(); }
        Invoke("RefreshVaultUi"); Pump();

        void Invoke(string name, params object?[] arguments) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, arguments);
        void Pump() { window.UpdateLayout(); window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle); window.UpdateLayout(); }
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (T descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void SaveElement(FrameworkElement element, string path)
    {
        var drawing = new DrawingVisual();
        using (DrawingContext context = drawing.RenderOpen())
            context.DrawRectangle(new VisualBrush(element), null, new Rect(element.RenderSize));
        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(element.ActualWidth), (int)Math.Ceiling(element.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(drawing);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string stagedPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = File.Create(stagedPath)) encoder.Save(file);
            File.Move(stagedPath, path, overwrite: true);
        }
        finally { if (File.Exists(stagedPath)) File.Delete(stagedPath); }
    }

    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }

    private static void CheckContentClip(Window window, double radius)
    {
        var content = (FrameworkElement)window.FindName("WindowContent");
        Check(content.Clip is RectangleGeometry clip && clip.RadiusX == radius && clip.RadiusY == radius
            && clip.Rect.Size == content.RenderSize, "Inner window backgrounds do not follow the frame contour.");
    }

    [DllImport("gdi32.dll")]
    private static extern nint CreateRectRgn(int left, int top, int right, int bottom);
    [DllImport("user32.dll")]
    private static extern int GetWindowRgn(nint window, nint region);
    [DllImport("gdi32.dll")]
    private static extern bool PtInRegion(nint region, int x, int y);
    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(nint item);
    [DllImport("dwmapi.dll")]
    private static extern int DwmGetWindowAttribute(nint window, int attribute, out uint value, uint size);

    private static void CheckNativeCorners(Window window)
    {
        nint region = CreateRectRgn(0, 0, 1, 1);
        Check(region != 0, "Unable to inspect the native window region.");
        try
        {
            nint handle = new WindowInteropHelper(window).Handle;
            if (GetWindowRgn(handle, region) > 1)
            {
                DpiScale dpi = VisualTreeHelper.GetDpi(window);
                // A six-DIP native radius passes the old (0,0) check but exposes
                // a dark crescent behind the twelve-DIP WPF frame.
                Check(!PtInRegion(region, (int)(3 * dpi.DpiScaleX), (int)(3 * dpi.DpiScaleY))
                    && PtInRegion(region, (int)(12 * dpi.DpiScaleX), (int)(12 * dpi.DpiScaleY)),
                    "Native corner cuts a smaller curve than the twelve-DIP visible frame.");
            }
            else
                Check(DwmGetWindowAttribute(handle, 33, out uint preference, sizeof(uint)) == 0 && preference == 2,
                    "Native DWM rounded corners were not applied.");
        }
        finally { DeleteObject(region); }
    }
}
