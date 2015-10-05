using System;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using System.Web;

namespace PassiveScanning.Cve
{
    public static class CveExtractor
    {
        public static List<CveDetail> GetMatchingCveDetails(string service)
        {
            List<CveDetail> matches = new List<CveDetail>();
            Regex versionRegex = new Regex("((?:(?:[^\\d]+ )*))(\\d(?:\\.\\d)+[a-z]*\\d*)");

            Match match = versionRegex.Match(service);
            if (!match.Success)
                throw new Exception("Failed to find match.");

            string serviceName = match.Groups[1].Value;
            string versionId = match.Groups[2].Value;

            List<CveDetail> cveDetails = GetCveDetails(serviceName);   
            foreach (CveDetail cveDetail in cveDetails)
            {
                if (cveDetail.IsVersionAffected(versionId))
                    matches.Add(cveDetail);
            }

            return matches;
        }

        private static List<CveDetail> GetCveDetails(string service)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers["user-agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36";
                client.Headers["https"] = "1";

                string detailsPage = FindCveDetailsPage(client, service);
                return FindDetails(client, detailsPage);
            }
        }

        private static string FindCveDetailsPage(WebClient client, string service)
        {
            string source = client.DownloadString(String.Format("https://www.google.com/search?as_q=" + HttpUtility.UrlEncode(service) + "&as_epq=&as_oq=&as_eq=&as_nlo=&as_nhi=&lr=&cr=&as_qdr=all&as_sitesearch=http%3A%2F%2Fwww.cvedetails.com%2F&as_occt=any&safe=images&as_filetype=&as_rights="));
            Regex regex = new Regex("https?://www.cvedetails.com/vulnerability-list/vendor_id-(\\d+)/product_id-(\\d+)/[\\w-]+\\.html");
            Match match = regex.Match(source);
            if (!match.Success)
                return null;

            return match.Captures[0].Value;
        }

        private static List<CveDetail> FindDetails(WebClient client, string page)
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
        }
    }
}

