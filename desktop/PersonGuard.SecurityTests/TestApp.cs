using System.Windows;
using System.Windows.Markup;
using System.IO;
using System.Xml.Linq;

// Render tests must not run the production bootstrap, acquire its mutex, or open real vaults.
internal sealed class TestApp : Application
{
    public void InitializeComponent()
    {
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var document = XDocument.Load(Path.Combine(Environment.CurrentDirectory, "desktop", "PersonGuard.Desktop", "App.xaml"));
        XElement dictionary = new(document.Descendants(presentation + "ResourceDictionary").First());
        dictionary.SetAttributeValue(XNamespace.Xmlns + "x", "http://schemas.microsoft.com/winfx/2006/xaml");
        dictionary.SetAttributeValue(XNamespace.Xmlns + "ui", "clr-namespace:PersonGuard.Desktop.Presentation;assembly=PersonGuard");
        XNamespace localUi = "clr-namespace:PersonGuard.Desktop.Presentation";
        XNamespace assemblyUi = "clr-namespace:PersonGuard.Desktop.Presentation;assembly=PersonGuard";
        foreach (XElement element in dictionary.Descendants().Where(element => element.Name.Namespace == localUi))
            element.Name = assemblyUi + element.Name.LocalName;
        string xaml = dictionary.ToString();
        Resources = (ResourceDictionary)XamlReader.Parse(xaml, new ParserContext
        {
            BaseUri = new Uri("pack://application:,,,/PersonGuard;component/App.xaml"),
        });
    }
}
