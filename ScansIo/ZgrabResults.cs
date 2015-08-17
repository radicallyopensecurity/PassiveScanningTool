using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace PassiveScanning
{
    public class ZgrabResults
    {
        public ZgrabResults(ushort port, string name, string file, HostList hosts, IPAddress[] dutchHosts)
        {
            StreamReader reader = new StreamReader("data/" + file);

            while (!reader.EndOfStream)
            {
                try
                {
                    string jsonString = reader.ReadLine();

                    int hostStringStart = jsonString.IndexOf("\"ip\":") + 6;
                    int hostStringEnd = jsonString.IndexOf('"', hostStringStart + 1) - 1;
                    string hostString = jsonString.Substring(hostStringStart, hostStringEnd - hostStringStart);

                    string banner = "";
                    if (jsonString.IndexOf("\"banner\":null") <= 0)
                    {
                        int bannerStringStart = jsonString.IndexOf("\"banner\":") + 10;
                        int bannerStringEnd = jsonString.IndexOf('"', bannerStringStart + 1) - 1;
                        banner = jsonString.Substring(bannerStringStart, bannerStringEnd - bannerStringStart);
                    }

                    IPAddress host = IPAddress.Parse(hostString);
                    if (!dutchHosts.Contains(host))
                        continue;

                    using (StreamWriter writer = new StreamWriter("output/" + host.ToString(), true))
                    {
                        writer.Write(host.ToString());
                        writer.Write(";");
                        writer.Write(name.Replace(';', ','));
                        writer.Write(";");
                        writer.Write(port.ToString());
                        writer.Write(";");
                        writer.Write(banner.Replace(';', ','));
                    }
                }
                catch
                {

                }
            }
        }
    }
}

