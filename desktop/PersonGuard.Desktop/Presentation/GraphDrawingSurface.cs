using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace PersonGuard.Desktop.Presentation;

/// <summary>One retained visual for the graph, rather than several controls per node.</summary>
public sealed class GraphDrawingSurface : FrameworkElement
{
    private readonly DrawingVisual _visual = new();
    private readonly List<(Rect Bounds, string Text)> _toolTips = [];
    private readonly List<string> _captions = [];
    private readonly List<Rect> _nodeBounds = [];
    private readonly Dictionary<Color, SolidColorBrush> _brushes = [];
    private readonly Typeface _regular;
    private readonly Typeface _bold;
    private DrawingContext? _context;
    private double _pixelsPerDip = 1;

    public GraphDrawingSurface()
    {
        var family = (FontFamily?)Application.Current?.TryFindResource("AppFont") ?? AppTypography.Family;
        _regular = new Typeface(family, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        _bold = new Typeface(family, FontStyles.Normal, FontWeights.Bold, FontStretches.Normal);
        AddVisualChild(_visual);
        TextOptions.SetTextRenderingMode(this, TextRenderingMode.ClearType);
        TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);
    }

    public IReadOnlyList<string> Captions => _captions;
    public IReadOnlyList<Rect> NodeBounds => _nodeBounds;
    public int Revision { get; private set; }
    protected override int VisualChildrenCount => 1;
    protected override Visual GetVisualChild(int index) => index == 0 ? _visual : throw new ArgumentOutOfRangeException(nameof(index));

    public void Draw(Size size, Action render)
    {
        Width = size.Width; Height = size.Height;
        _toolTips.Clear(); _captions.Clear(); _nodeBounds.Clear(); ToolTip = null;
        _pixelsPerDip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        using DrawingContext context = _visual.RenderOpen();
        _context = context;
        try { render(); Revision++; }
        finally { _context = null; }
    }

    public void Clear()
    {
        using (_visual.RenderOpen()) { }
        _toolTips.Clear(); _captions.Clear(); _nodeBounds.Clear(); ToolTip = null;
        _brushes.Clear();
        Width = Height = 0;
        Revision++;
    }

    public void Line(double x1, double y1, double x2, double y2, Color color, double thickness) =>
        _context!.DrawLine(Pen(color, thickness), new Point(x1, y1), new Point(x2, y2));

    public void WebLine(double x1, double y1, double x2, double y2, Color color, double thickness)
    {
        double dx = x2 - x1, dy = y2 - y1;
        var path = new StreamGeometry();
        using (StreamGeometryContext geometry = path.Open())
        {
            geometry.BeginFigure(new Point(x1, y1), false, false);
            geometry.QuadraticBezierTo(new Point((x1 + x2) / 2 - dy * .055, (y1 + y2) / 2 + dx * .055), new Point(x2, y2), true, false);
        }
        path.Freeze();
        _context!.DrawGeometry(null, Pen(color, thickness), path);
    }

    public void Orbit(double x, double y, double radiusX, double radiusY, Color color)
    {
        var pen = new Pen(Brush(color), 1) { DashStyle = new DashStyle(new double[] { 3, 7 }, 0) };
        pen.Freeze();
        _context!.DrawEllipse(null, pen, new Point(x, y), radiusX, radiusY);
    }

    public void Node(double x, double y, double radius, Color fill, Color stroke, string label, string caption, double captionWidth, string toolTip, double glowOpacity)
    {
        var center = new Point(x, y);
        Color glow = Color.FromArgb((byte)Math.Round(255 * glowOpacity), stroke.R, stroke.G, stroke.B);
        _context!.DrawEllipse(Brush(glow), null, center, radius + 5, radius + 5);
        _context.DrawEllipse(Brush(fill), Pen(stroke, 1.7), center, radius, radius);
        Text(label, x - radius, y - 9, radius * 2, radius < 20 ? 11 : 13, true, Color.FromRgb(244, 247, 251));
        Text(caption, x - captionWidth / 2, y + radius + 8, captionWidth, radius < 20 ? 11 : 12, false,
            radius < 20 ? Color.FromRgb(137, 151, 174) : Color.FromRgb(216, 226, 242));
        _captions.Add(caption);
        var bounds = new Rect(x - captionWidth / 2, y - radius - 5, captionWidth, radius * 2 + 43);
        _nodeBounds.Add(bounds);
        _toolTips.Add((bounds, toolTip));
    }

    private void Text(string value, double x, double y, double width, double size, bool bold, Color color)
    {
        var text = new FormattedText(value, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            bold ? _bold : _regular, size, Brush(color), _pixelsPerDip)
        {
            MaxTextWidth = width, MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis,
            TextAlignment = TextAlignment.Center,
        };
        _context!.DrawText(text, new Point(x, y));
    }

    private SolidColorBrush Brush(Color color)
    {
        if (_brushes.TryGetValue(color, out var brush)) return brush;
        brush = new SolidColorBrush(color); brush.Freeze();
        _brushes[color] = brush;
        return brush;
    }

    private Pen Pen(Color color, double thickness)
    {
        var pen = new Pen(Brush(color), thickness); pen.Freeze(); return pen;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        Point point = e.GetPosition(this);
        string? text = null;
        for (int index = _toolTips.Count - 1; index >= 0; index--)
            if (_toolTips[index].Bounds.Contains(point)) { text = _toolTips[index].Text; break; }
        if (!Equals(ToolTip, text)) ToolTip = text;
    }

    protected override void OnMouseLeave(MouseEventArgs e) { ToolTip = null; base.OnMouseLeave(e); }
}
