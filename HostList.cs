using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Collections.Generic;

namespace PassiveScanning
{
    public class HostList
    {
        public Dictionary<IPAddress, Host> Hosts;

        public HostList(string file)
        {
            string[] lines = File.ReadAllLines("nl.csv");
            Hosts = new Dictionary<IPAddress, Host>(4096 * lines.Length);

            foreach (var line in lines)
            {
                string[] tokens = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2)
                    break;

                string fromIpString = tokens[0];
                string toIpString = tokens[1];

                try
                {
                    IPAddress fromIp = IPAddress.Parse(fromIpString);
                    IPAddress toIp = IPAddress.Parse(toIpString);
                    IPAddress incrementedToIp = toIp.Increment();

                    for (IPAddress ipIterator = fromIp; !ipIterator.Equals(incrementedToIp); ipIterator = ipIterator.Increment())
                        Hosts.Add(ipIterator, new Host(ipIterator));
                }
                catch
                {

                }
            }
        }
    }
}

