using System;
using System.Net;
using System.Collections.Generic;

namespace PassiveScanning
{
    [Serializable]
    public class Host
    {
        public IPAddress Address
        {
            get;
            private set;
        }

        public string AddressString
        {
            get;
            private set;
        }

        public List<Service> Services = new List<Service>();

        public Host(IPAddress address)
        {
            Address = address;
            AddressString = Address.ToString();
        }
    }
}

