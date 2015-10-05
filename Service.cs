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

        public JObject Data
        {
            get;
            private set;
        }

        public string RawData
        {
            get;
            private set;
        }

        public Service(ushort port, string name, string rawData, JObject data)
        {
            Port = port;
            Name = name;
            Data = data;
        }
    }
}

