using System;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace PassiveScanning
{
    public class ResultProcessor
    {
        private string m_resultPath;

        public ResultProcessor(string resultPath)
        {
            m_resultPath = resultPath;
        }

        public IPAddress[] GetRandomHosts(int count)
        {
            int lines = Utilities.CountLines(m_resultPath);

            List<string> addresses = new List<string>(lines);

            using (StreamReader reader = new StreamReader(m_resultPath))
            {
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    if (String.IsNullOrEmpty(line))
                        continue;

                    int hostStringStart = line.IndexOf("\"ip\":") + 6;
                    int hostStringEnd = line.IndexOf('"', hostStringStart + 1);
                    string hostString = line.Substring(hostStringStart, hostStringEnd - hostStringStart);

                    if (!addresses.Contains(hostString))
                        addresses.Add(hostString);
                }
            }

            List<IPAddress> randomHosts = new List<IPAddress>(count);
            List<int> lastIndices = new List<int>(count);
            Random random = new Random(Environment.TickCount);

            for (int i = 0; i < count; i++)
            {
                int index;
                do
                {
                    index = random.Next(0, addresses.Count);
                } while(lastIndices.Contains(index));

                lastIndices.Add(index);
                randomHosts.Add(IPAddress.Parse(addresses[index]));
            }

            return randomHosts.ToArray();
        }

        public int FillHostInformation(List<Host> hosts)
        {
            List<String> hostStrings = (from h in hosts select h.AddressString).ToList();

            int serviceCounter = 0;
            using (StreamReader reader = new StreamReader(m_resultPath))
            {
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    if (String.IsNullOrEmpty(line))
                        continue;

                    int hostStringStart = line.IndexOf("\"ip\":") + 6;
                    int hostStringEnd = line.IndexOf('"', hostStringStart + 1);
                    string hostString = line.Substring(hostStringStart, hostStringEnd - hostStringStart);

                    if (hostStrings.Contains(hostString))
                    {
                        Host host = hosts.Single(h => h.AddressString == hostString);

                        string[] tokens = line.Split(new char[] { ';' }, 4);
                        string service = tokens[1];
                        int port = Int32.Parse(tokens[2]);
                        JObject data = Newtonsoft.Json.Linq.JObject.Parse(tokens[3]);
                        Service serv = new Service((ushort)port, service, data);
                        host.Services.Add(serv);
                        serviceCounter++;
                    }
                }
            }

            return serviceCounter;
        }
    }
}

