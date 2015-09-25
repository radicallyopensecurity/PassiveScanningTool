using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;

namespace PassiveScanning
{
    public class ZgrabResults
    {
        public ZgrabResults(ushort port, string name, string file, IPAddress[] dutchHosts)
        {
            using (StreamWriter writer = new StreamWriter("data/output/services-" + name, true))
            using (StreamReader reader = new StreamReader("data/" + file))
            {
                while (!reader.EndOfStream)
                {
                    try
                    {
                        string jsonString = reader.ReadLine();

                        string hostString;
                        if (name == "IMAP" || name == "Heartbleed")
                        {
                            int hostStringStart = jsonString.IndexOf("\"host\":") + 8;
                            int hostStringEnd = jsonString.IndexOf('"', hostStringStart + 1);
                            hostString = jsonString.Substring(hostStringStart, hostStringEnd - hostStringStart);
                        }
                        else
                        {
                            int hostStringStart = jsonString.IndexOf("\"ip\":") + 6;
                            int hostStringEnd = jsonString.IndexOf('"', hostStringStart + 1);
                            hostString = jsonString.Substring(hostStringStart, hostStringEnd - hostStringStart);
                        }

                        IPAddress host = IPAddress.Parse(hostString);
                        if (!dutchHosts.Contains(host))
                            continue;

                        writer.Write(host.ToString());
                        writer.Write(";");
                        writer.Write(name.Replace(';', ','));
                        writer.Write(";");
                        writer.Write(port.ToString());
                        writer.Write(";");
                        writer.Write(jsonString.Replace(';', ','));
                        writer.WriteLine();
                    }
                    catch
                    {

                    }
                }
            }
        }
    }
}

