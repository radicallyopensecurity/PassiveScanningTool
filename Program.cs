using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using PassiveScanning.Cve;
using PassiveScanning.ScansIo;
using PassiveScanning.Shodan;
using System.Linq;
using System.Threading;

namespace PassiveScanning
{
    class MainClass
    {
        public static CveDocument CveDocument;
        public static HostList HostList;

        public static void Main(string[] args)
        {
            if (Directory.Exists("data/output"))
                Directory.Delete("data/output", true);
            Directory.CreateDirectory("data/output");

            ThreadPool.SetMaxThreads(2, 1);
            ThreadPool.SetMinThreads(1, 1);

            Console.WriteLine("Loading list of dutch hosts...");

            HostList = new HostList("nl.csv");
            Console.WriteLine("Found {0} dutch hosts.", HostList.Hosts.Count);

            FindServiceDescriptor[] services = new FindServiceDescriptor[]
            { 
                new FindServiceDescriptor(143, "IMAP", FindZmapFile("143-imap-starttls-full_ipv4", true), FindZmapFile("143-imap-starttls-full_ipv4", false)),
                new FindServiceDescriptor(21, "FTP", FindZmapFile("21-ftp-banner-full_ipv4", true), FindZmapFile("21-ftp-banner-full_ipv4", false)),
                new FindServiceDescriptor(995, "POP3S", FindZmapFile("995-pop3s-tls-full_ipv4", true), FindZmapFile("995-pop3s-tls-full_ipv4", false)),
                new FindServiceDescriptor(443, "Heartbleed", FindZmapFile("443-https-heartbleed-full_ipv4", true), FindZmapFile("443-https-heartbleed-full_ipv4", false)),
                new FindServiceDescriptor(25, "SMTP", FindZmapFile("25-smtp-starttls-full_ipv4", true), FindZmapFile("25-smtp-starttls-full_ipv4", false)),
                new FindServiceDescriptor(993, "IMAPS", FindZmapFile("993-imaps-tls-full_ipv4", true), FindZmapFile("993-imaps-tls-full_ipv4", false)),
                new FindServiceDescriptor(443, "HTTPS", FindZmapFile("443-https-tls-full_ipv4", true), FindZmapFile("443-https-tls-full_ipv4", false)),
                new FindServiceDescriptor(110, "POP3", FindZmapFile("110-pop3-starttls-full_ipv4", true), FindZmapFile("110-pop3-starttls-full_ipv4", false)),
                new FindServiceDescriptor("HTTP", FindRapid7File("http"))
            };

            foreach (var service in services)
                ThreadPool.QueueUserWorkItem(FindServices, service);

            Console.WriteLine("Synchronizing threads...");
            foreach (var service in services)
                service.WaitHandle.WaitOne();

            Console.WriteLine("Done.");

            CveDocument = new CveDocument();

            if (!Directory.Exists("output"))
                Directory.CreateDirectory("output");

            string resultPath = "/media/koen/2.3.2-22-amd641/output";
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

            List<string> hostIPs = new List<string>();
            foreach (var host in hostList)
                hostIPs.Add(host.AddressString);

            File.WriteAllLines("hosts.txt", hostIPs);

            Console.WriteLine("Searching for software banners/versions and CVE's...");
            FindAndDumpSoftwareBannersAndCves(hostList);
            Console.WriteLine("Searching for Heartbleed...");
            FindAndDumpHeartbleed(resultPath, hostList);
            Console.WriteLine("Done!");

            List<Host> shodanHostList;
            if (!File.Exists("ShodanHostInformation"))
            {
                Console.WriteLine("Loading Shodan host list...");
                shodanHostList = GetHostListFromShodan(hostList.Select(h => h.AddressString).ToList());
                Console.WriteLine("Found {0} Shodan hosts.", shodanHostList.Count);

                Utilities.SaveObject("ShodanHostInformation", shodanHostList);
            }
            else
            {
                Console.WriteLine("Loading Shodan host information...");
                shodanHostList = (List<Host>)Utilities.LoadObject("ShodanHostInformation");
            }

            Console.WriteLine("Searching for Shodan software banners/versions and CVE's...");
            FindAndDumpSoftwareBannersAndCves(shodanHostList, "shodan-");

            Console.WriteLine("Searching Shodan for comments on websites...");
            FindAndProcessWebsiteComments(shodanHostList);
        }

        public static void FindAndProcessWebsiteComments(List<Host> hostList)
        {
            Console.WriteLine("Total hosts: {0}.", hostList.Count);

            int counter = 0;
            foreach (var host in hostList)
            {
                Console.WriteLine("Processing host {0}.", ++counter);

                //host.FillHostnames();
                var hostNames = host.HostNames;
                if (hostNames == null)
                    hostNames = new List<string>(new string[] { host.AddressString });
                else
                    hostNames.Add(host.AddressString);

                hostNames = hostNames.Distinct().ToList();

                List<string> comments = new List<string>();
                foreach (var hostName in hostNames)
                {
                    Console.WriteLine("Processing hostname {0}.", hostName);

                    var commentList = GetCommentsFromArchiveOrg(hostName);
                    if (commentList == null)
                        continue;

                    comments.AddRange(commentList);
                }

                comments = comments.Distinct().ToList();
                foreach (var comment in comments)
                    Console.WriteLine(comment);
            }//);
        }

        public static List<string> GetCommentsFromArchiveOrg(string hostName)
        {
            string source = GetSourceFromArchiveOrg(hostName);
            if (source == null)
                return null;

            return GetCommentsFromSource(source);
        }

        public static List<string> GetCommentsFromSource(string source)
        {
            Regex regex = new Regex(@"<!--([\.\w\-/#_\s/:]+)-->");

            List<string> comments = new List<string>();
            MatchCollection matches = regex.Matches(source);
            foreach (Match match in matches)
                comments.Add(match.Groups[1].Value);

            return comments;
        }

        public static string GetSourceFromArchiveOrg(string hostname)
        {
            using (WebClient client = new WebClient())
            {
                string resultString = null;

                try
                {
                    resultString = client.DownloadString("http://archive.org/wayback/available?url=" + hostname);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to load archive for '{0}': {1}", hostname, e.Message);
                    return null;
                }

                JObject result = JObject.Parse(resultString);
                JObject closestToken = (JObject)result.SelectToken("archived_snapshots.closest");

                if (closestToken == null)
                    return null;

                bool available = false;
                JToken availableToken;
                if (closestToken.TryGetValue("available", out availableToken))
                    available = availableToken.Value<bool>();

                string url = null;
                JToken urlToken;
                if (closestToken.TryGetValue("url", out urlToken))
                    url = urlToken.Value<string>();

                if (available && url != null)
                    return client.DownloadString(url);
            }

            return null;
        }

        public static List<Host> GetHostListFromShodan(List<string> ips)
        {
            List<Host> hostList = new List<Host>();
            ShodanWeb shodan = new ShodanWeb("APIKEY");

            int hostCounter = 0;
            Console.WriteLine("Total hosts: " + ips.Count);

            Parallel.ForEach(ips, ip =>
            //foreach (var ip in ips)
                {
                    JObject hostObject = shodan.GetHost(ip);  
                    if (hostObject == null)
                    {
                        Console.WriteLine("Skipped host {0} with ip {1} due to a Shodan error.", ++hostCounter, ip);
                        return;
                        //continue;
                    }
                            
                    JToken errorToken;
                    if (hostObject.TryGetValue("error", out errorToken))
                    {
                        Console.WriteLine("Skipped host {0} with ip {1}: {2}.", ++hostCounter, ip, errorToken.Value<string>());
                        return;
                        //continue;
                    }

                    Host host = new Host(IPAddress.Parse(ip));
                    host.HostNames = new List<string>();

                    JToken hostNames;
                    if (hostObject.TryGetValue("hostnames", out hostNames))
                    {
                        JArray hostNamesArray = (JArray)hostNames;
                        host.HostNames.AddRange(hostNamesArray.ToObject<string[]>());
                    }

                    JToken dataToken;
                    if (hostObject.TryGetValue("data", out dataToken))
                    {
                        string module = "";
                        string port = "0";
                        string product = null;
                        string version = null;
                        string banner = "";

                        foreach (JToken dataChild in dataToken.Children())
                        {
                            var dataChildObject = (JObject)dataChild;

                            JToken productToken;
                            if (dataChildObject.TryGetValue("product", out productToken))
                                product = productToken.Value<string>();

                            JToken versionToken;
                            if (dataChildObject.TryGetValue("version", out versionToken))
                                version = versionToken.Value<string>();

                            JToken shodanToken = dataChildObject.Property("_shodan");
                            var shodanChildrenArray = shodanToken.Children().ToArray();
                            if (shodanChildrenArray.Length > 0)
                            {
                                var childrenArray = shodanChildrenArray[0].Children().ToArray();
                                if (childrenArray.Length > 0)
                                {
                                    JProperty moduleToken = (JProperty)childrenArray[0];
                                    module = moduleToken.Value.Value<string>().ToUpper();
                                }
                            }

                            JToken portToken;
                            if (dataChildObject.TryGetValue("port", out portToken))
                                port = portToken.Value<string>();

                            JToken bannerToken;
                            if (dataChildObject.TryGetValue("banner", out bannerToken))
                                banner = bannerToken.Value<string>();

                            Service service = new Service(ushort.Parse(port), module, null);
                            service.Product = product;
                            service.Version = version;
                            service.Banner = banner;

                            host.Services.Add(service);

                            lock (hostList)
                                hostList.Add(host);
                        }

                        Console.WriteLine("Loaded {0} hosts from Shodan.", ++hostCounter);
                    }
                });

            return hostList;
        }

        public static void FindAndDumpHeartbleed(string resultPath, List<Host> hostList)
        {
            List<string> heartbleedHosts = GetHeartbleedHosts(resultPath, hostList);
            DumpHeartbleedHosts(hostList, heartbleedHosts);
        }

        public static void FindAndDumpSoftwareBannersAndCves(List<Host> hostList, string prefix = "")
        {
            var bannerCounters = FindBannersFromHostList(hostList);
            
            Dictionary<string, Dictionary<string, int>> softwareCounter = new Dictionary<string, Dictionary<string, int>>();
            Dictionary<string, int> totalSoftwareCounter = new Dictionary<string, int>();
            Dictionary<string, Dictionary<CveDetail, int>> cveDetailsCounter = new Dictionary<string, Dictionary<CveDetail, int>>(); 
            GetSoftwareAndCveFromBanners(bannerCounters, ref softwareCounter, ref totalSoftwareCounter, ref cveDetailsCounter);

            DumpSoftwareFrequencies(softwareCounter, totalSoftwareCounter, prefix);
            DumpCveFrequencies(cveDetailsCounter, totalSoftwareCounter, prefix);

            var missingHTTPHeaderCounter = FindMissingHTTPHeaders(hostList);
            DumpMissingHTTPHeaders(hostList, missingHTTPHeaderCounter);
        }

        public static void DumpHeartbleedHosts(List<Host> hostList, List<string> heartbleedHosts)
        {
            using (StreamWriter writer = new StreamWriter("output/heartbleed-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);
                writer.WriteLine("Heartbleed: " + heartbleedHosts.Count);
            }
        }

        public static void DumpMissingHTTPHeaders(List<Host> hostList, Dictionary<string, int> missingHTTPHeaderCounter)
        {
            using (StreamWriter writer = new StreamWriter("output/missing-http-header-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);

                foreach (var pair in missingHTTPHeaderCounter)
                    writer.WriteLine(pair.Key + ";" + pair.Value);
            }

            /*using (StreamWriter writer = new StreamWriter("missing-https-header-frequency", false))
            {
                writer.WriteLine("Total hosts: " + hostList.Count);

                foreach (var pair in missingHTTPSHeaderCounter)
                    writer.WriteLine(pair.Key + ";" + pair.Value);
            }*/
        }

        public static Dictionary<string, int> FindMissingHTTPHeaders(List<Host> hostList)
        {
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

            return missingHTTPHeaderCounter;
        }

        public static void DumpCveFrequencies(Dictionary<string, Dictionary<CveDetail, int>> cveDetailsCounter, Dictionary<string, int> totalSoftwareCounter, string prefix = "")
        {
            foreach (var pair in cveDetailsCounter)
            {
                using (StreamWriter writer = new StreamWriter("output/" + prefix + "cve-frequency-" + pair.Key, false))
                {
                    writer.WriteLine("Total {0}: {1}", pair.Key, totalSoftwareCounter[pair.Key]);
                    foreach (var frequencyPair in pair.Value)
                        writer.WriteLine(frequencyPair.Key.CVE + ';' + frequencyPair.Key.Score + ';' + frequencyPair.Value);
                }
            }
        }

        public static void DumpSoftwareFrequencies(Dictionary<string, Dictionary<string, int>> softwareCounter, Dictionary<string, int> totalSoftwareCounter, string prefix = "")
        {
            foreach (var pair in softwareCounter)
            {
                using (StreamWriter writer = new StreamWriter("output/" + prefix + "software-frequency-" + pair.Key, false))
                {
                    writer.WriteLine("Total {0}: {1}", pair.Key, totalSoftwareCounter[pair.Key]);
                    foreach (var frequencyPair in pair.Value)
                        writer.WriteLine(frequencyPair.Key + ';' + frequencyPair.Value);
                }
            }
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

        public static void GetSoftwareAndCveFromBanners(Dictionary<string, Dictionary<string, int>> bannerCounters, ref Dictionary<string, Dictionary<string, int>> softwareCounter, ref Dictionary<string, int> totalSoftwareCounter, ref Dictionary<string, Dictionary<CveDetail, int>> cveDetailsCounter)
        {
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

                        //Console.WriteLine(software + ";" + bannerFrequencyPair.Value);

                        List<CveDetail> cveDetails = CveDocument.GetAffectedCves(software);
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

                        List<CveDetail> cveDetails = CveDocument.GetAffectedCves(software);
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
        }

        public static void DumpBanners(Dictionary<string, Dictionary<string, int>> bannerCounters, string prefix = "")
        {
            foreach (var pair in bannerCounters)
            {
                var bannerCounter = pair.Value;

                using (StreamWriter writer = new StreamWriter("output/" + prefix + "banner-" + pair.Key, false))
                {
                    foreach (var bannerFrequencyPair in bannerCounter)
                    {
                        string text = String.Format("{0};{1}", bannerFrequencyPair.Key, bannerFrequencyPair.Value);
                        //Console.WriteLine(text);
                        writer.WriteLine(text);
                    }
                }
            }
        }

        public static Dictionary<string, Dictionary<string, int>> FindBannersFromHostList(List<Host> hostList)
        {
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
                        if (service.Product != null && service.Version != null)
                        {
                            string banner = service.Product + " " + service.Version;
                            if (bannerCounter.ContainsKey(banner))
                                bannerCounter[banner]++;
                            else
                                bannerCounter.Add(banner, 1);
                        }
                        else if (service.Name == "HTTP")
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
                        else if (service.Name == "IMAP")
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

            return bannerCounters;
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
        
        public static string FindRapid7File(string name)
        {
            Regex regex = new Regex("[0-9]{8}-(\\w+)");
            return Directory.GetFiles("data").First(f => regex.IsMatch(f) && f.ToLower().Contains(name.ToLower())).Substring(5);
        }

        public static string FindZmapFile(string name, bool zgrab)
        {
            return Directory.GetFiles("data").First(f => f.ToLower().Contains(name.ToLower()) && f.ToLower().Contains(zgrab ? "zgrab-results" : "zmap-results")).Substring(5);
        }
    }
}
