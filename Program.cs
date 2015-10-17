using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using PassiveScanning.Cve;
using PassiveScanning.ScansIo;

namespace PassiveScanning
{
    class MainClass
    {
        public static HostList HostList;

        public static void Main(string[] args)
        {
            if (!Directory.Exists("output"))
                Directory.CreateDirectory("output");

            Console.WriteLine("Loading CVE database.");
            CveDocument document = new CveDocument();

            string resultPath = "/media/koen/2.3.2-22-amd64/output";
            ResultProcessor results = new ResultProcessor(resultPath);

            List<string> uniqueHttpAddressList;
            if (!File.Exists("UniqueAddressList"))
            {
                Console.WriteLine("Generating unique address list...");
                uniqueHttpAddressList = results.GetUniqueAddressList(true);
                Utilities.SaveObject("UniqueAddressList", uniqueHttpAddressList);
            }
            else
            {
                Console.WriteLine("Loading unique address list...");
                uniqueHttpAddressList = (List<string>)Utilities.LoadObject("UniqueAddressList");
            }

            Console.WriteLine("Found {0} unique HTTP servers.", uniqueHttpAddressList.Count);

            int randomHostCount = Utilities.CalculateSampleSize(uniqueHttpAddressList.Count);

            Console.WriteLine("Fetching {0} random hosts.", randomHostCount);
            IPAddress[] randomHosts = results.GetRandomHosts(randomHostCount, uniqueHttpAddressList);

            Console.WriteLine("{0} random hosts fetched.", randomHosts.Length);

            List<Host> hostList;
            if (!File.Exists("HostInformation"))
            {
                hostList = new List<Host>(randomHosts.Length);

                Console.WriteLine("Generating host information...");

                for (int i = 0; i < randomHosts.Length; i++)
                    hostList.Add(new Host(randomHosts[i]));

                results.FillHostInformation(hostList);

                Console.WriteLine("Generated host information.");

                Utilities.SaveObject("HostInformation", hostList);
            }
            else
            {
                Console.WriteLine("Loading host information...");
                hostList = (List<Host>)Utilities.LoadObject("HostInformation");
            }


            Dictionary<string, Dictionary<string, int>> bannerCounters = new Dictionary<string, Dictionary<string, int>>();
            foreach (var host in hostList)
            {
                foreach (var service in host.Services)
                {
                    Dictionary<string, int> bannerCounter;
                    if (bannerCounters.ContainsKey(service.Name))
                        bannerCounter = bannerCounters[service.Name];
                    else
                    {
                        bannerCounter = new Dictionary<string, int>();
                        bannerCounters.Add(service.Name, bannerCounter);
                    }

                    try
                    {
                        if (service.Name == "HTTP")
                        {
                            JObject data = JObject.Parse(service.RawData);

                            string banner = Encoding.ASCII.GetString(Convert.FromBase64String(data["data"].Value<string>()));
                            int index = banner.IndexOf("server:", StringComparison.OrdinalIgnoreCase);
                            if (index < 0)
                                banner = "Unknown";
                            else
                            {
                                index += "server:".Length;
                                int endIndex = banner.IndexOf("\n", index);
                                banner = banner.Substring(index, endIndex - index).Trim();
                            }

                            if (bannerCounter.ContainsKey(banner))
                                bannerCounter[banner]++;
                            else
                                bannerCounter.Add(banner, 1);                            
                        }
                        if (service.Name == "IMAP")
                        {
                            JObject data = JObject.Parse(service.RawData);

                            var logNode = data["log"];
                            var typeDataNode = logNode[1];
                            var dataNode = typeDataNode["data"];
                            var bannerNode = dataNode["banner"];
                            string banner = bannerNode.Value<string>();
                            if (bannerCounter.ContainsKey(banner))
                                bannerCounter[banner]++;
                            else
                                bannerCounter.Add(banner, 1);
                        }
                        else
                        {
                            JObject data = JObject.Parse(service.RawData);

                            string banner = data["data"]["banner"].Value<string>();
                            if (bannerCounter.ContainsKey(banner))
                                bannerCounter[banner]++;
                            else
                                bannerCounter.Add(banner, 1);
                        }
                    }
                    catch
                    {
                    }
                }
            }

            foreach (var pair in bannerCounters)
            {
                var bannerCounter = pair.Value;

                using (StreamWriter writer = new StreamWriter("output/banner-" + pair.Key, false))
                {
                    foreach (var bannerFrequencyPair in bannerCounter)
                    {
                        string text = String.Format("{0};{1}", bannerFrequencyPair.Key, bannerFrequencyPair.Value);
                        Console.WriteLine(text);
                        writer.WriteLine(text);
                    }
                }
            }

            Dictionary<string, Dictionary<string, int>> softwareCounter = new Dictionary<string, Dictionary<string, int>>();
            Dictionary<string, int> totalSoftwareCounter = new Dictionary<string, int>();
            Dictionary<string, Dictionary<CveDetail, int>> cveDetailsCounter = new Dictionary<string, Dictionary<CveDetail, int>>(); 

            foreach (var pair in bannerCounters)
            {
                if (pair.Key == "HTTP")
                {
                    int total = 0;
                    Dictionary<string, int> counter = new Dictionary<string, int>();
                    Dictionary<CveDetail, int> cveCounter = new Dictionary<CveDetail, int>();

                    Regex regex = new Regex(@"(?:[a-zA-Z/\-_\.]+[ /])+v?\d+(?:\.\d+)*[a-z]?(?:-[^ ;]+)?");
                    foreach (var bannerFrequencyPair in pair.Value)
                    {
                        total += bannerFrequencyPair.Value;

                        Match match = regex.Match(bannerFrequencyPair.Key);
                        if (!match.Success)
                            continue;

                        string software = match.Captures[0].Value;
                        if (counter.ContainsKey(software))
                            counter[software] += bannerFrequencyPair.Value;
                        else
                            counter.Add(software, bannerFrequencyPair.Value);

                        Console.WriteLine(software + ";" + bannerFrequencyPair.Value);

                        List<CveDetail> cveDetails = document.GetAffectedCves(software);
                        foreach (var cveDetail in cveDetails)
                        {
                            if (cveCounter.ContainsKey(cveDetail))
                                cveCounter[cveDetail] += bannerFrequencyPair.Value;
                            else
                                cveCounter.Add(cveDetail, bannerFrequencyPair.Value);
                        }
                    }

                    cveDetailsCounter.Add(pair.Key, cveCounter);
                    softwareCounter.Add(pair.Key, counter);
                    totalSoftwareCounter.Add(pair.Key, total);
                }
                else
                {
                    int total = 0;
                    Dictionary<string, int> counter = new Dictionary<string, int>();
                    Dictionary<CveDetail, int> cveCounter = new Dictionary<CveDetail, int>();

                    Regex regex = new Regex(@"(?!\d)(?:[a-zA-Z\.\d]+[ \-_])+v?(?:\d+(?:\.\d+)+(?:rc\d+|[a-z])?)");
                    foreach (var bannerFrequencyPair in pair.Value)
                    {
                        total += bannerFrequencyPair.Value;

                        Match match = regex.Match(bannerFrequencyPair.Key);
                        if (!match.Success)
                            continue;

                        string software = match.Captures[0].Value;
                        if (counter.ContainsKey(software))
                            counter[software] += bannerFrequencyPair.Value;
                        else
                            counter.Add(software, bannerFrequencyPair.Value);

                        List<CveDetail> cveDetails = document.GetAffectedCves(software);
                        foreach (var cveDetail in cveDetails)
                        {
                            if (cveCounter.ContainsKey(cveDetail))
                                cveCounter[cveDetail] += bannerFrequencyPair.Value;
                            else
                                cveCounter.Add(cveDetail, bannerFrequencyPair.Value);
                        }
                    }

                    cveDetailsCounter.Add(pair.Key, cveCounter);
                    softwareCounter.Add(pair.Key, counter);
                    totalSoftwareCounter.Add(pair.Key, total);
                }
            }

            foreach (var pair in softwareCounter)
            {
                using (StreamWriter writer = new StreamWriter("output/software-frequency-" + pair.Key, false))
                {
                    writer.WriteLine("Total {0}: {1}", pair.Key, totalSoftwareCounter[pair.Key]);
                    foreach (var frequencyPair in pair.Value)
                        writer.WriteLine(frequencyPair.Key + ';' + frequencyPair.Value);
                }
            }

            foreach (var pair in cveDetailsCounter)
            {
                using (StreamWriter writer = new StreamWriter("output/cve-frequency-" + pair.Key, false))
                {
                    writer.WriteLine("Total {0}: {1}", pair.Key, totalSoftwareCounter[pair.Key]);
                    foreach (var frequencyPair in pair.Value)
                        writer.WriteLine(frequencyPair.Key.CVE + ';' + frequencyPair.Key.Score + ';' + frequencyPair.Value);
                }
            }

            Dictionary<string, int> missingHTTPHeaderCounter = new Dictionary<string, int>();
            //Dictionary<string, int> missingHTTPSHeaderCounter = new Dictionary<string, int>();

            foreach (var host in hostList)
            {
                foreach (string s in host.GetMissingHTTPHeaders())
                {
                    if (missingHTTPHeaderCounter.ContainsKey(s))
                        missingHTTPHeaderCounter[s]++;
                    else
                        missingHTTPHeaderCounter.Add(s, 1);
                }

                /*foreach (string s in host.GetMissingHTTPSHeaders())
                {
                    if (missingHTTPSHeaderCounter.ContainsKey(s))
                        missingHTTPSHeaderCounter[s]++;
                    else
                        missingHTTPSHeaderCounter.Add(s, 1);
                }*/
            }

            using (StreamWriter writer = new StreamWriter("output/missing-http-header-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);

                foreach (var pair in missingHTTPHeaderCounter)
                    writer.WriteLine(pair.Key + ";" + pair.Value);
            }

            List<string> heartbleedHosts = GetHeartbleedHosts(resultPath, hostList);

            using (StreamWriter writer = new StreamWriter("output/heartbleed-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);
                writer.WriteLine("Heartbleed: " + heartbleedHosts.Count);
            }

            /*using (StreamWriter writer = new StreamWriter("missing-https-header-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);

                foreach (var pair in missingHTTPSHeaderCounter)
                    writer.WriteLine(pair.Key + ";" + pair.Value);
            }*/

            //TODO: Algoritme, CVE's bepalen en linken
            //foreach (var cve in document.GetAffectedCves("Proftpd 1.3.5"))
            //    Console.WriteLine("Exploit with score {0} fits: {1}", cve.Score, cve.Description);

            /*if (Directory.Exists("data/output"))
                Directory.Delete("data/output", true);
            Directory.CreateDirectory("data/output");

            ThreadPool.SetMaxThreads(2, 1);
            ThreadPool.SetMinThreads(1, 1);

            Console.WriteLine("Loading list of dutch hosts...");

            HostList = new HostList("nl.csv");
            Console.WriteLine("Found {0} dutch hosts.", HostList.Hosts.Count);

            FindServiceDescriptor[] services = new FindServiceDescriptor[]
            { 
                new FindServiceDescriptor(143, "IMAP", "5elhwfrqv15nq5px-143-imap-starttls-full_ipv4-20150617T163103-zgrab-results.json", "5elhwfrqv15nq5px-143-imap-starttls-full_ipv4-20150617T163103-zmap-results.csv"),
                new FindServiceDescriptor(21, "FTP", "7ngdfqqrhmqdce38-21-ftp-banner-full_ipv4-20150801T233003-zgrab-results.json", "7ngdfqqrhmqdce38-21-ftp-banner-full_ipv4-20150801T233003-zmap-results.csv"),
                new FindServiceDescriptor(995, "POP3S", "gf1z452301hyhs3w-995-pop3s-tls-full_ipv4-20150802T140000-zgrab-results.json", "gf1z452301hyhs3w-995-pop3s-tls-full_ipv4-20150802T140000-zmap-results.csv"),
                new FindServiceDescriptor(443, "Heartbleed", "ju8g62b9picx0i3i-443-https-heartbleed-full_ipv4-20150706T000000-zgrab-results.json", "ju8g62b9picx0i3i-443-https-heartbleed-full_ipv4-20150706T000000-zmap-results.csv"),
                new FindServiceDescriptor(25, "SMTP", "klnqp1y00vooeonh-25-smtp-starttls-full_ipv4-20150803T040000-zgrab-results.json", "klnqp1y00vooeonh-25-smtp-starttls-full_ipv4-20150803T040000-zmap-results.csv"),
                new FindServiceDescriptor(993, "IMAPS", "pt15h1gy6uic493j-993-imaps-tls-full_ipv4-20150721T120000-zgrab-results.json", "pt15h1gy6uic493j-993-imaps-tls-full_ipv4-20150721T120000-zmap-results.csv"),
                new FindServiceDescriptor(443, "HTTPS", "ydns0pmlsiu0996u-443-https-tls-full_ipv4-20150804T010006-zgrab-results.json", "ydns0pmlsiu0996u-443-https-tls-full_ipv4-20150804T010006-zmap-results.csv"),
                new FindServiceDescriptor(110, "POP3", "z2nk2bbxgipkjl9k-110-pop3-starttls-full_ipv4-20150729T221221-zgrab-results.json", "z2nk2bbxgipkjl9k-110-pop3-starttls-full_ipv4-20150729T221221-zmap-results.csv"),
                new FindServiceDescriptor("HTTP", "20150721-http")
            };

            foreach (var service in services)
                ThreadPool.QueueUserWorkItem(FindServices, service);

            Console.WriteLine("Synchronizing threads...");
            foreach (var service in services)
                service.WaitHandle.WaitOne();

            Console.WriteLine("Done.");*/
        }

        public static List<string> GetHeartbleedHosts(string resultPath, List<Host> hostList)
        {
            List<string> heartbleedHosts = new List<string>(hostList.Count);

            using (StreamReader reader = new StreamReader(Path.Combine(resultPath, "services-Heartbleed")))
            {
                while (!reader.EndOfStream)
                {
                    string line;

                    try
                    {
                        line = reader.ReadLine();
                        if (!line.Contains("\"heartbleed_vulnerable\":true"))
                            continue;

                        foreach (var host in hostList)
                        {
                            if (line.StartsWith(host.AddressString))
                            {
                                heartbleedHosts.Add(host.AddressString);
                                break;
                            }
                        }
                    }
                    catch
                    {

                    }
                }
            }

            return heartbleedHosts;
        }

        public static void FindServices(object state)
        {
            FindServiceDescriptor findServiceDescriptor = (FindServiceDescriptor)state;
            
            try
            {
                if (String.IsNullOrEmpty(findServiceDescriptor.Rapid7Path))
                {
                    Console.WriteLine("Loading ZMAP {0}-Banner results...", findServiceDescriptor.Name);

                    ZmapResults mapResults = new ZmapResults(findServiceDescriptor.ZmapResultsPath, HostList);
                    Console.WriteLine("Found Dutch {0} hosts with {1}.", mapResults.Addresses.Length, findServiceDescriptor.Name);

                    Console.WriteLine("Fetching banners for Dutch {0} hosts...", findServiceDescriptor.Name);
                    ZgrabResults grabResults = new ZgrabResults(findServiceDescriptor.Port, findServiceDescriptor.Name, findServiceDescriptor.ZgrabResultsPath, mapResults.Addresses);
                }
                else
                {
                    Console.WriteLine("Loading {0}-Rapid7 results...", findServiceDescriptor.Name);

                    Rapid7Results results = new Rapid7Results(findServiceDescriptor.Name, findServiceDescriptor.Rapid7Path, HostList);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("An exception occurred while finding services: {0}.", e.ToString());
            }
            finally
            {
                Console.WriteLine("{0} is done.", findServiceDescriptor.Name);
                findServiceDescriptor.WaitHandle.Set();
            }
        }
    }
}
