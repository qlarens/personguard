using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace PersonGuard.Desktop.Presentation;

// Center the visible glyph, rather than its font's asymmetric line box.
public sealed class CenteredGlyph : Control
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(CenteredGlyph),
        new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.AffectsRender | FrameworkPropertyMetadataOptions.AffectsMeasure));
    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }

    protected override Size MeasureOverride(Size constraint) => new(FontSize + 6, FontSize + 6);

    protected override void OnRender(DrawingContext context)
    {
        base.OnRender(context);
        if (Text == "×")
        {
            var pen = new Pen(Foreground, 1.5);
            double x = ActualWidth / 2, y = ActualHeight / 2;
            context.DrawLine(pen, new Point(x - 4, y - 4), new Point(x + 4, y + 4));
            context.DrawLine(pen, new Point(x + 4, y - 4), new Point(x - 4, y + 4));
            return;
        }
        var text = new FormattedText(Text ?? string.Empty, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface(FontFamily, FontStyle, FontWeight, FontStretch), FontSize, Foreground, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        Rect ink = text.BuildGeometry(new Point()).Bounds;
        if (!ink.IsEmpty)
            context.DrawText(text, new Point((ActualWidth - ink.Width) / 2 - ink.X, (ActualHeight - ink.Height) / 2 - ink.Y));
    }
}
