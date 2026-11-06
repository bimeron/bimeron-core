using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Linq;
public static class DurationXml {
 const string Ns="http://schemas.microsoft.com/windows/2004/02/mit/task";
 static XmlDocument Parse(string xml) {
  var settings=new XmlReaderSettings { DtdProcessing=DtdProcessing.Prohibit, XmlResolver=null };
  var doc=new XmlDocument { PreserveWhitespace=true, XmlResolver=null };
  using(var reader=XmlReader.Create(new StringReader(xml),settings)) doc.Load(reader);
  return doc;
 }
 static void Token(StringBuilder b,string value) {b.Append(value.Length).Append(':').Append(value);}
 static void Walk(XmlNode n,StringBuilder b) {
  if(n.NodeType==XmlNodeType.XmlDeclaration || n.NodeType==XmlNodeType.Whitespace || n.NodeType==XmlNodeType.SignificantWhitespace)return;
  if(n.NodeType==XmlNodeType.Text && String.IsNullOrWhiteSpace(n.Value))return;
  Token(b,n.NodeType.ToString());
  if(n.NodeType==XmlNodeType.Element) {
   Token(b,n.NamespaceURI);Token(b,n.LocalName);
   var attrs=n.Attributes.Cast<XmlAttribute>().Where(a=>a.NamespaceURI!="http://www.w3.org/2000/xmlns/").OrderBy(a=>a.NamespaceURI,StringComparer.Ordinal).ThenBy(a=>a.LocalName,StringComparer.Ordinal).ToArray();
   Token(b,attrs.Length.ToString());foreach(var a in attrs){Token(b,a.NamespaceURI);Token(b,a.LocalName);Token(b,a.Value);}
  } else if(n.NodeType!=XmlNodeType.Document){Token(b,n.Name);Token(b,n.Value??"");}
  foreach(XmlNode c in n.ChildNodes)Walk(c,b);Token(b,"end");
 }
 public static string Canonical(string xml,string expectedDuration,bool normalize) {
  var d=Parse(xml);var ns=new XmlNamespaceManager(d.NameTable);ns.AddNamespace("t",Ns);
  var nodes=d.SelectNodes("/t:Task/t:Settings/t:ExecutionTimeLimit",ns);
  if(nodes.Count!=1 || nodes[0].InnerText!=expectedDuration)throw new InvalidDataException("Duration node/value mismatch");
  if(nodes[0].ChildNodes.Cast<XmlNode>().Any(n=>n.NodeType!=XmlNodeType.Text))throw new InvalidDataException("Duration content shape");
  if(normalize)nodes[0].InnerText="PT3M";
  var b=new StringBuilder();Walk(d,b);return b.ToString();
 }
 public static void EqualExceptDuration(string before,string after,string afterDuration) {
  if(Canonical(before,"PT3M",false)!=Canonical(after,afterDuration,true))throw new InvalidDataException("XML changed beyond permitted duration");
 }
}
