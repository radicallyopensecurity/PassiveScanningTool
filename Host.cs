using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace PassiveScanning
{
    [Serializable]
    public class Host
    {
        public IPAddress Address
        {
            get;
            private set;
        }

        public string AddressString
        {
            get;
            private set;
        }

        public List<Service> Services = new List<Service>();

        public Host(IPAddress address)
        {
            Address = address;
            AddressString = Address.ToString();
        }

        public string GetHostname()
        {
            using (WebClient client = new WebClient())
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                string responseString = client.UploadString("https://www.whatismyip.com/custom/response.php", "hostname" + AddressString + "=&action=hostname-lookup");
                int start = responseString.IndexOf('>') + 1;
                int end = responseString.IndexOf('<', start);

                string hostName = responseString.Substring(start, end - start);
                return hostName;
            }
        }

        public bool HasHeartbleed(string resultPath)
        {
            using (StreamReader reader = new StreamReader(Path.Combine(resultPath, "services-Heartbleed")))
            {
                while (!reader.EndOfStream)
                {
                    string line;

                    try
                    {
                        line = reader.ReadLine();
                        if (!line.StartsWith(AddressString))
                            continue;

                        return true;
                    }
                    catch
                    {

                    }
                }
            }

            return false;
        }

        public List<string> GetMissingHTTPHeaders()
        {
            List<string> missingHeaders = new List<string>();

            Regex matchCookieRegex = new Regex("set-cookie: .+", RegexOptions.IgnoreCase);

            try
            {
                Service service = Services.Single(s => s.Name == "HTTP");
                JObject data = JObject.Parse(service.RawData);

                string banner = Encoding.ASCII.GetString(Convert.FromBase64String(data["data"].Value<string>())).ToUpper();
                
                foreach (Match match in matchCookieRegex.Matches(banner))
                {
                    if (!match.Captures[0].Value.Contains("HttpOnly"))
                    {
                        missingHeaders.Add("HttpOnly");
                        break;       
                    }
                }

                Regex matchXFrameOptionsRegex = new Regex("X-Frame-Options", RegexOptions.IgnoreCase);
                if (!matchXFrameOptionsRegex.Match(banner).Success)
                    missingHeaders.Add("X-Frame-Options");

                Regex matchContentSecurityPolicyRegex = new Regex("Content-Security-Policy", RegexOptions.IgnoreCase);
                if (!matchContentSecurityPolicyRegex.Match(banner).Success)
                    missingHeaders.Add("Content-Security-Policy");

                Regex matchContentTypeOptionsRegex = new Regex("X-Content-Type-Options", RegexOptions.IgnoreCase);
                if (!matchContentTypeOptionsRegex.Match(banner).Success)
                    missingHeaders.Add("X-Content-Type-Options");
            }
            catch
            {

            }

            return missingHeaders;
        }

        public List<string> GetMissingHTTPSHeaders()
        {
            List<string> missingHeaders = new List<string>();

            Regex matchCookieRegex = new Regex("set-cookie: .+", RegexOptions.IgnoreCase);

            try
            {
                Service service = Services.Single(s => s.Name == "HTTPS");
                JObject data = JObject.Parse(service.RawData);

                string banner = Encoding.ASCII.GetString(Convert.FromBase64String(data["data"].Value<string>())).ToUpper();
                
                foreach (Match match in matchCookieRegex.Matches(banner))
                {
                    if (!match.Captures[0].Value.Contains("HttpOnly"))
                    {
                        if (!missingHeaders.Contains("HttpOnly"))
                            missingHeaders.Add("HttpOnly");
                    }
                    else if (!match.Captures[0].Value.Contains("Secure"))
                    {
                        if (!missingHeaders.Contains("Secure"))
                            missingHeaders.Add("Secure");
                    }
                }

                Regex matchXFrameOptionsRegex = new Regex("X-Frame-Options", RegexOptions.IgnoreCase);
                if (!matchXFrameOptionsRegex.Match(banner).Success)
                    missingHeaders.Add("X-Frame-Options");

                Regex matchContentSecurityPolicyRegex = new Regex("Content-Security-Policy", RegexOptions.IgnoreCase);
                if (!matchContentSecurityPolicyRegex.Match(banner).Success)
                    missingHeaders.Add("Content-Security-Policy");

                Regex matchContentTypeOptionsRegex = new Regex("X-Content-Type-Options", RegexOptions.IgnoreCase);
                if (!matchContentTypeOptionsRegex.Match(banner).Success)
                    missingHeaders.Add("X-Content-Type-Options");

                Regex matchStrictTransportSecurityRegex = new Regex("X-Content-Type-Options", RegexOptions.IgnoreCase);
                if (!matchStrictTransportSecurityRegex.Match(banner).Success)
                    missingHeaders.Add("Strict-Transport-Security");
            }
            catch (Exception e)
            {
                //Console.WriteLine(e.Message);
                //Console.ReadLine();
            }

            return missingHeaders;
        }
    }
}

