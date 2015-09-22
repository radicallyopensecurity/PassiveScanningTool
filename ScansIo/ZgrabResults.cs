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
        public static StreamWriter ServicesWriter;
        public static Mutex ServiceWriterMutex = new Mutex();

        public ZgrabResults(ushort port, string name, string file, HostList hosts, IPAddress[] dutchHosts)
        {
            StreamReader reader = new StreamReader("data/" + file);

            while (!reader.EndOfStream)
            {
                try
                {
                    string jsonString = reader.ReadLine();

                    int hostStringStart = jsonString.IndexOf("\"ip\":") + 6;
                    int hostStringEnd = jsonString.IndexOf('"', hostStringStart + 1);
                    string hostString = jsonString.Substring(hostStringStart, hostStringEnd - hostStringStart);

                    IPAddress host = IPAddress.Parse(hostString);
                    if (!dutchHosts.Contains(host))
                        continue;

                    ServiceWriterMutex.WaitOne();

                    try
                    {
                        ServicesWriter.Write(host.ToString());
                        ServicesWriter.Write(";");
                        ServicesWriter.Write(name.Replace(';', ','));
                        ServicesWriter.Write(";");
                        ServicesWriter.Write(port.ToString());
                        ServicesWriter.Write(";");
                        ServicesWriter.Write(jsonString.Replace(';', ','));
                        ServicesWriter.WriteLine();
                    }
                    finally
                    {
                        ServiceWriterMutex.ReleaseMutex();
                    }
                }
                catch
                {

                }
            }
        }
    }
}

