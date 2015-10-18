using System;
using Newtonsoft.Json.Linq;

namespace PassiveScanning
{
    [Serializable]
    public class Service
    {
        public ushort Port
        {
            get;
            private set;
        }

        public string Name
        {
            get;
            private set;
        }

        public string RawData
        {
            get;
            private set;
        }

        public string Product = null;
        public string Version = null;
        public string Banner = null;

        public Service(ushort port, string name, string rawData)
        {
            Port = port;
            Name = name;
            RawData = rawData;
        }
    }
}

