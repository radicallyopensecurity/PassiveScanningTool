using System;

namespace PassiveScanning.Cve
{
    [Serializable]
    public class CveId
    {
        public int Year
        {
            get;
            private set;
        }

        public int Identifier
        {
            get;
            private set;
        }

        public CveId(string cveId)
        {
            string[] tokens = cveId.Split('-');
            Year = int.Parse(tokens[1]);
            Identifier = int.Parse(tokens[2]);
        }

        public override string ToString()
        {
            return "CVE-" + Year.ToString() + "-" + Identifier.ToString().PadLeft(4, '0');
        }

        public override int GetHashCode()
        {
            return (Year << 16) | Identifier;
        }

        public override bool Equals(object o)
        {
            if (o == null || !(o is CveId))
                return false;

            CveId b = (CveId)o;
            return Year == b.Year && Identifier == b.Identifier;
        }

        public static bool operator==(CveId a, CveId b)
        {
            return a.Equals(b);
        }

        public static bool operator!=(CveId a, CveId b)
        {
            return !a.Equals(b);
        }
    }
}

