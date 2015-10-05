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

        public int CountServices(bool onlyHttp)
        {
            string[] files;
            if (!onlyHttp)
                files = Directory.GetFiles(m_resultPath);
            else
                files = new string[] { Path.Combine(m_resultPath, "services-HTTP") };

            int lines = 0;
            foreach (string file in files)
                lines += Utilities.CountLines(file);

            return lines;
        }

        public List<string> GetUniqueAddressList(bool onlyHttp)
        {
            string[] files;
            if (!onlyHttp)
                files = Directory.GetFiles(m_resultPath);
            else
                files = new string[] { Path.Combine(m_resultPath, "services-HTTP") };

            List<string> addressList = new List<string>(CountServices(onlyHttp));

            foreach (string file in files)
            {
                using (StreamReader reader = new StreamReader(file))
                {
                    while (!reader.EndOfStream)
                    {
                        string line = reader.ReadLine();
                        if (String.IsNullOrEmpty(line))
                            continue;

                        int hostStringStart = line.IndexOf("\"ip\":") + 7;
                        int hostStringEnd = line.IndexOf('"', hostStringStart + 1);
                        string hostString = line.Substring(hostStringStart, hostStringEnd - hostStringStart);

                        //not needed, address list is properly distributed
                        //if (!addressList.Contains(hostString))
                        addressList.Add(hostString);
                    }
                }
            }

            return addressList;
        }

        public IPAddress[] GetRandomHosts(int count, List<string> addresses)
        {
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

        public IPAddress[] GetRandomHosts(int count, bool onlyHttp)
        {
            string[] files;
            if (!onlyHttp)
                files = Directory.GetFiles(m_resultPath);
            else
                files = new string[] { Path.Combine(m_resultPath, "services-HTTP") };

            List<string> addresses = GetUniqueAddressList(onlyHttp);
            return GetRandomHosts(count, addresses);
        }

        public int FillHostInformation(List<Host> hosts)
        {
            List<String> hostStrings = (from h in hosts
                                                 select h.AddressString).ToList();

            int serviceCounter = 0;
            foreach (string file in Directory.GetFiles(m_resultPath))
            {
                using (StreamReader reader = new StreamReader(file))
                {
                    while (!reader.EndOfStream)
                    {
                        string line = reader.ReadLine();
                        if (String.IsNullOrEmpty(line))
                            continue;

                        int hostStringEnd = line.IndexOf(';');
                        string hostString = line.Substring(0, hostStringEnd);

                        if (hostStrings.Contains(hostString))
                        {
                            Host host = hosts.Single(h => h.AddressString == hostString);

                            string[] tokens = line.Split(new char[] { ';' }, 4);
                            string service = tokens[1];
                            int port = Int32.Parse(tokens[2]);

                            Service serv = new Service((ushort)port, service, tokens[3]);
                            host.Services.Add(serv);
                            serviceCounter++;
                        }
                    }
                }
            }

            return serviceCounter;
        }
    }
}

