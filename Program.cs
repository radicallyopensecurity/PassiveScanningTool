using System;
using System.Linq;
using PassiveScanning.ScansIo;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Threading;
using System.Runtime.Serialization;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Collections.Generic;

namespace PassiveScanning
{
    class MainClass
    {
        public static HostList HostList;

        public static void Main(string[] args)
        {
            /*ResultProcessor results = new ResultProcessor("/media/koen/2.3.2-22-amd641/services");
            IPAddress[] randomHosts = results.GetRandomHosts(384);

            Console.WriteLine("{0} random hosts fetched.", randomHosts.Length);

            List<Host> hostList = new List<Host>(randomHosts.Length);
            for (int i = 0; i < randomHosts.Length; i++)
                hostList.Add(new Host(randomHosts[i]));

            results.FillHostInformation(hostList);

            Console.WriteLine("Filled host information.");

            Dictionary<string, int> bannerCounter = new Dictionary<string, int>();
            foreach (var host in hostList)
            {
                foreach (var service in host.Services)
                {
                    try
                    {
                        string banner = service.Data["data"]["banner"].Value<string>();
                        if (bannerCounter.ContainsKey(banner))
                            bannerCounter[banner]++;
                        else
                            bannerCounter.Add(banner, 1);
                    }
                    catch
                    {
                    }
                }
            }

            foreach (var bannerFrequencyPair in bannerCounter)
            {
                Console.WriteLine("{0};{1}", bannerFrequencyPair.Key, bannerFrequencyPair.Value);
            }*/

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
                new FindServiceDescriptor(143, "IMAP", "5elhwfrqv15nq5px-143-imap-starttls-full_ipv4-20150617T163103-zgrab-results.json", "5elhwfrqv15nq5px-143-imap-starttls-full_ipv4-20150617T163103-zmap-results.csv"),
                new FindServiceDescriptor(21, "FTP", "7ngdfqqrhmqdce38-21-ftp-banner-full_ipv4-20150801T233003-zgrab-results.json", "7ngdfqqrhmqdce38-21-ftp-banner-full_ipv4-20150801T233003-zmap-results.csv"),
                new FindServiceDescriptor(995, "POP3S", "gf1z452301hyhs3w-995-pop3s-tls-full_ipv4-20150802T140000-zgrab-results.json", "gf1z452301hyhs3w-995-pop3s-tls-full_ipv4-20150802T140000-zmap-results.csv"),
                new FindServiceDescriptor(443, "Heartbleed", "ju8g62b9picx0i3i-443-https-heartbleed-full_ipv4-20150706T000000-zgrab-results.json", "ju8g62b9picx0i3i-443-https-heartbleed-full_ipv4-20150706T000000-zmap-results.csv"),
                new FindServiceDescriptor(25, "SMTP", "klnqp1y00vooeonh-25-smtp-starttls-full_ipv4-20150803T040000-zgrab-results.json","klnqp1y00vooeonh-25-smtp-starttls-full_ipv4-20150803T040000-zmap-results.csv"),
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

            Console.WriteLine("Done.");
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
