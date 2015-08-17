using System;

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

        public string Banner
        {
            get;
            private set;
        }

        public Service(ushort port, string name, string banner)
        {
            Port = port;
            Name = name;
            Banner = banner;
        }
    }
}

