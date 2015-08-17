using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;

namespace PassiveScanning.ScansIo
{
    public class ZmapResults
    {
        public IPAddress[] Addresses;

        public ZmapResults(string file, HostList hosts)
        {
            StreamReader reader = new StreamReader("data/" + file);

            List<IPAddress> addresses = new List<IPAddress>(hosts.Hosts.Count);

            while (!reader.EndOfStream)
            {
                try
                {
                    string ipString = reader.ReadLine();
                    IPAddress address = IPAddress.Parse(ipString);

                    lock (hosts.Hosts)
                    {
                        if (hosts.Hosts.Keys.Contains(address))
                            addresses.Add(address);
                    }
                }
                catch
                {

                }
            }

            Addresses = addresses.ToArray();
        }
    }
}

