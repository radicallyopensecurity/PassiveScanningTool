
using System.Net;
using Newtonsoft.Json.Linq;
using System;
using System.Threading;

namespace PassiveScanning.Shodan
{
    public class ShodanWeb
    {
        private readonly string m_shodanUrl = "https://api.shodan.io";
        private readonly string m_apiKey;

        public ShodanWeb(string apiKey)
        {
            m_apiKey = apiKey;
        }

        public JObject GetHost(string ip)
        {
            return MakeRequest("/shodan/host/" + ip + "?key=" + m_apiKey);
        }

        public JObject MakeRequest(string url)
        {
            try
            {
                using (WebClient client = new WebClient())
                    return JObject.Parse(client.DownloadString(m_shodanUrl + url));
            }
            catch
            {
                return null;
            }
        }
    }
}