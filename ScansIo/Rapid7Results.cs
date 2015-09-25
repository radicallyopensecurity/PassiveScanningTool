using System;
using System.IO;
using System.Threading;
using System.Net;
using System.Linq;

namespace PassiveScanning
{
    public class Rapid7Results
    {
        public Rapid7Results(string name, string file, HostList hosts)
        {
            using (StreamWriter writer = new StreamWriter("data/output/services-" + name, true))
            using (StreamReader reader = new StreamReader("data/" + file))
            {
                while (!reader.EndOfStream)
                {
                    try
                    {
                        string jsonString = reader.ReadLine();

                        int hostStringStart = jsonString.LastIndexOf("\"ip\":") + 7;
                        int hostStringEnd = jsonString.IndexOf('"', hostStringStart);
                        string hostString = jsonString.Substring(hostStringStart, hostStringEnd - hostStringStart);

                        IPAddress host = IPAddress.Parse(hostString);
                        lock (hosts.Hosts)
                        {
                            if (!hosts.Hosts.Keys.Contains(host))
                                continue;
                        }

                        int portStringStart = jsonString.LastIndexOf("\"port\":") + 8;
                        int portStringEnd = jsonString.IndexOf(',', portStringStart);
                        string portString = jsonString.Substring(portStringStart, portStringEnd - portStringStart);

                        writer.Write(host.ToString());
                        writer.Write(";");
                        writer.Write(name.Replace(';', ','));
                        writer.Write(";");
                        writer.Write(portString);
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

