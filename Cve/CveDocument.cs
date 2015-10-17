using System;
using System.Xml;
using System.Collections.Generic;
using System.IO;
using System.Xml.Linq;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.RegularExpressions;

namespace PassiveScanning.Cve
{
    public class CveDocument
    {
        private Dictionary<CveId, CveDetail> m_cveDetails = new Dictionary<CveId, CveDetail>();

        public CveDocument()
        {
            if (File.Exists("CveDatabase"))
            {
                Console.WriteLine("Loading CVE database...");
                Load("CveDatabase");
            }
            else
            {
                if (!Directory.Exists("nvdcve"))
                {
                    Console.WriteLine("Expected 'nvdcve' directory to exist containing all 'nvdcve' XML files.");
                    return;
                }

                Console.WriteLine("Importing CVE database...");
                LoadNvdCveDirectory("nvdcve");

                Console.WriteLine("Saving CVE database...");
                Save("CveDatabase");
            }

            Console.WriteLine("CVE database loaded.");
        }

        public void Load(string path)
        {
            using (FileStream input = File.OpenRead(path))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                m_cveDetails = (Dictionary<CveId, CveDetail>)formatter.Deserialize(input);
            }
        }

        public void Save(string path)
        {
            using (FileStream output = File.OpenWrite(path))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(output, m_cveDetails);
            }
        }

        public void LoadNvdCveDirectory(string path)
        {
            foreach (string file in Directory.GetFiles(path))
                LoadNvdCve(file);
        }

        public void LoadNvdCve(string path)
        {
            XDocument document = XDocument.Load(path);

            foreach (var node in document.Descendants())
            {
                if (node.Name.LocalName != "entry")
                    continue;

                CveId id = new CveId(node.Attribute("id").Value);
                CveDetail detail = new CveDetail();

                List<string> versions = null;

                try
                {
                    var vulnerableVersions = node.Descendants().Single(d => d.Name.LocalName == "vulnerable-software-list").Descendants().ToArray();
                    versions = new List<string>(vulnerableVersions.Length);

                    foreach (XElement vulnerableVersion in vulnerableVersions)
                    {
                        string[] tokens = vulnerableVersion.Value.Split(':');
                        detail.Company = tokens[2];
                        detail.ServiceName = tokens[3];
                        if (tokens.Length > 4)
                            versions.Add(tokens[4]);
                    }
                }
                catch
                {
                    Console.WriteLine("Skipped " + id.ToString());
                    continue;
                }

                detail.CVE = node.Descendants().Single(d => d.Name.LocalName == "cve-id").Value;
                CveId cveId = new CveId(detail.CVE);

                detail.CWE = TryGetDescendantAttributeValue(node, "cwe", "id");
                detail.PublishDate = TryGetDescendantValue(node, "published-datetime");
                detail.UpdateDate = TryGetDescendantValue(node, "last-modified-datetime");

                var cvssNode = node.Descendants().Single(d => d.Name.LocalName == "cvss").Descendants().First();
                detail.Score = double.Parse(cvssNode.Descendants().Single(d => d.Name.LocalName == "score").Value);
                detail.GainedAccessLevel = "";
                detail.Access = cvssNode.Descendants().Single(d => d.Name.LocalName == "access-vector").Value;
                detail.Complexity = cvssNode.Descendants().Single(d => d.Name.LocalName == "access-complexity").Value;
                detail.Authentication = cvssNode.Descendants().Single(d => d.Name.LocalName == "authentication").Value;
                detail.Confidentiality = cvssNode.Descendants().Single(d => d.Name.LocalName == "confidentiality-impact").Value;
                detail.Integrity = cvssNode.Descendants().Single(d => d.Name.LocalName == "integrity-impact").Value;
                detail.Availability = cvssNode.Descendants().Single(d => d.Name.LocalName == "availability-impact").Value;

                detail.Description = node.Descendants().Single(d => d.Name.LocalName == "summary").Value;

                if (versions == null)
                    versions = new List<string>();

                detail.AffectedVersions = versions.ToArray();

                if (!m_cveDetails.ContainsKey(cveId))
                    m_cveDetails.Add(cveId, detail);
            }
        }

        private string TryGetDescendantAttributeValue(XElement node, string name, string attribute)
        {
            var child = node.Descendants().FirstOrDefault(d => d.Name.LocalName == name);
            if (child != null)
                return child.Attribute(attribute).Value;
            return "";
        }

        private string TryGetDescendantValue(XElement node, string name)
        {
            var child = node.Descendants().SingleOrDefault(d => d.Name.LocalName == name);
            if (child != null)
                return child.Value;
            return "";
        }

        public List<CveDetail> GetCveDetails(string serviceName)
        {
            List<CveDetail> details = new List<CveDetail>();
            foreach (var detail in m_cveDetails.Values)
            {
                if (serviceName.IndexOf(detail.ServiceName, StringComparison.OrdinalIgnoreCase) >= 0)
                    details.Add(detail);
            }

            return details;
        }

        public List<CveDetail> GetAffectedCves(string version)
        {
            string serviceName;
            string versionId;

            
            try
            {
                Regex versionRegex = new Regex(@"((?:(?:[^\d]+[ /])*))(\d+(?:\.\d+)+[a-z]*\d*)");

                Match match = versionRegex.Match(version);
                if (!match.Success)
                    throw new Exception("Failed to find match for string '" + version + "'.");

                serviceName = match.Groups[1].Value;
                versionId = match.Groups[2].Value;
            }
            catch
            {
                Regex versionRegex = new Regex(@"(\w+)/(\d)");

                Match match = versionRegex.Match(version);
                if (!match.Success)
                {
                    Console.WriteLine("Failed to find match for string '" + version + "'.");
                    return new List<CveDetail>();
                }

                serviceName = match.Groups[1].Value;
                versionId = match.Groups[2].Value;
            }
            
            List<CveDetail> cveDetails = GetCveDetails(serviceName);
            List<CveDetail> affectedCveDetails = new List<CveDetail>();
            foreach (CveDetail cveDetail in cveDetails)
            {
                if (cveDetail.IsVersionAffected(versionId))
                    affectedCveDetails.Add(cveDetail);
            }
            
            return affectedCveDetails;
        }

        /* LEGACY CODE FOR cvedetails.com
        public static List<CveDetail> GetCveDetails(string service)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers["user-agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36";
                client.Headers["https"] = "1";

                string detailsPage = FindCveDetailsPage(client, service);
                return FindDetails(client, detailsPage);
            }
        }

        public static string FindCveDetailsPage(WebClient client, string service)
        {
            string source = client.DownloadString(String.Format("https://www.google.com/search?as_q=" + HttpUtility.UrlEncode(service) + "&as_epq=&as_oq=&as_eq=&as_nlo=&as_nhi=&lr=&cr=&as_qdr=all&as_sitesearch=http%3A%2F%2Fwww.cvedetails.com%2F&as_occt=any&safe=images&as_filetype=&as_rights="));
            Regex regex = new Regex("https?://www.cvedetails.com/vulnerability-list/vendor_id-(\\d+)/product_id-(\\d+)/[\\w-]+\\.html");
            Match match = regex.Match(source);
            if (!match.Success)
                return null;

            return match.Captures[0].Value;
        }

        public static List<CveDetail> FindDetails(WebClient client, string page)
        {
            List<CveDetail> results = new List<CveDetail>();

            //Todo, support for multiple pages?
            string source = client.DownloadString(page);
            HtmlDocument document = new HtmlDocument();
            document.LoadHtml(source);

            HtmlNode headerNode = document.DocumentNode.SelectSingleNode("//div[@id=\"contentdiv\"]/h1");
            string serviceName = headerNode.ChildNodes[1].InnerText;

            HtmlNodeCollection nodes = document.DocumentNode.SelectNodes("//tr[@class='srrowns']");
            foreach (HtmlNode node in nodes)
            {
                HtmlNodeCollection children = node.ChildNodes;
                string description = node.NextSibling.NextSibling.InnerText;

                CveDetail detail = new CveDetail(serviceName, children, description);
                results.Add(detail);
            }

            return results;
        }*/
    }
}

