using System;
using System.Net;
using System.Collections.Generic;

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
    }
}

