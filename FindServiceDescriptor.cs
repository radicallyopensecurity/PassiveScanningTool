using System;
using System.Threading;

namespace PassiveScanning
{
    public class FindServiceDescriptor
    {
        public ushort Port;
        public string Name;
        public string ZgrabResultsPath;
        public string ZmapResultsPath;
        public string Rapid7Path;
        public AutoResetEvent WaitHandle; 

        public FindServiceDescriptor(ushort port, string name, string zgrabPath, string zmapPath)
        {
            Port = port;
            Name = name;
            ZgrabResultsPath = zgrabPath;
            ZmapResultsPath = zmapPath;
            WaitHandle = new AutoResetEvent(false);
        }

        public FindServiceDescriptor(string name, string rapid7Path)
        {
            Name = name;
            Rapid7Path = rapid7Path;
            WaitHandle = new AutoResetEvent(false);
        }
    }
}

