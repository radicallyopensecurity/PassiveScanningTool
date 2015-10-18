using System;
using HtmlAgilityPack;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Linq;

namespace PassiveScanning.Cve
{
    [Serializable]
    public class CveDetail
    {
        public string ServiceName;
        public string Description;
        public string CVE;
        public string CWE;
        public string PublishDate;
        public string UpdateDate;
        public double Score;
        public string GainedAccessLevel;
        public string Access;
        public string Complexity;
        public string Authentication;
        public string Confidentiality;
        public string Integrity;
        public string Availability;
        public string Company;
        public string[] AffectedVersions;

        private static Regex VersionRegex = new Regex("(\\d(?:\\.\\d)+)([a-z]*)(\\d*)");

        public CveDetail()
        {
            
        }

        /* LEGACY
        public CveDetail(string serviceName, HtmlNodeCollection cveNodes, string description)
        {
            ServiceName = serviceName;

            CVE = cveNodes[3].InnerText;
            CWE = cveNodes[5].InnerText;
            PublishDate = cveNodes[11].InnerText;
            UpdateDate = cveNodes[13].InnerText;
            Score = double.Parse(cveNodes[15].InnerText);
            GainedAccessLevel = cveNodes[17].InnerText;
            Access = cveNodes[19].InnerText;
            Complexity = cveNodes[21].InnerText;
            Authentication = cveNodes[23].InnerText;
            Confidentiality = cveNodes[25].InnerText;
            Integrity = cveNodes[27].InnerText;
            Availability = cveNodes[29].InnerText;

            Description = description;

            AffectedVersions = GetAffectedVersions().ToArray();
        }*/

        /* LEGACY
        private List<string> GetAffectedVersions()
        {
            int index = Description.IndexOf(ServiceName, 0, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
                throw new Exception("Failed to find affected version.");

            List<string> versions = new List<string>();

            bool before = false;
            Regex versionRegex = new Regex("\\d(?:\\.\\d)+[a-z]*\\d*");
            int index1 = index + ServiceName.Length + 1;

            while (true)
            {
                int index2 = Description.IndexOf(" ", index1);
                string keyword = Description.Substring(index1, index2 - index1);
                keyword = keyword.Replace(",", "");

                if (keyword != "and")
                {
                    if (keyword == "before")
                        before = true;
                    else
                    {
                        if (versionRegex.Match(keyword).Success)
                        {
                            if (before)
                            {
                                keyword = "<" + keyword;
                                before = false;
                            }
                            versions.Add(keyword);
                        }
                        else
                            break;
                    }
                }

                index1 = index2 + 1;
            }

            return versions;
        } */

        public bool IsVersionAffected(string version)
        {
            Match match1 = VersionRegex.Match(version);
            string mainVersion1 = match1.Groups[1].Value;
            string subversion1 = match1.Groups[2].Value;
            string releaseCandidate1 = match1.Groups[3].Value;

            foreach (string affectedVersion in AffectedVersions)
            {
                if (version.StartsWith("<"))
                {
                    Match match2 = VersionRegex.Match(version);
                    string mainVersion2 = match2.Groups[1].Value;
                    string subversion2 = match2.Groups[2].Value;
                    string releaseCandidate2 = match2.Groups[3].Value;

                    if (IsMainVersion1LessThanMainVersion2(mainVersion1, mainVersion2))
                        return true;

                    if (mainVersion1 == mainVersion2)
                    {
                        if (subversion1.ToLower() != "r" && subversion1.ToLower() != "rc" && subversion2.ToLower() != "r" && subversion2.ToLower() != "rc" && IsSubVersion1LessThanSubVersion2(subversion1, subversion2))
                            return true;

                        if (subversion1 == subversion2)
                        {
                            if (releaseCandidate1.Length == 0 && releaseCandidate2.Length > 0)
                                return true;

                            if (releaseCandidate1.Length > 0 && releaseCandidate2.Length > 0)
                            {
                                if (int.Parse(releaseCandidate1) < int.Parse(releaseCandidate2))
                                    return true;
                            }
                        }
                    }
                }
                else if (version.ToLower() == affectedVersion.ToLower())
                //else if (affectedVersion.IndexOf(version, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private bool IsMainVersion1LessThanMainVersion2(string version1, string version2)
        {
            string[] tokens1 = version1.Split('.');
            int[] numbers1 = tokens1.Select(v => int.Parse(v)).ToArray();
            string[] tokens2 = version2.Split('.');
            int[] numbers2 = tokens2.Select(v => int.Parse(v)).ToArray();

            if (numbers1.Length != numbers2.Length)
                throw new Exception("Version string length unmatched.");

            for (int i = 0; i < numbers1.Length; i++)
            {
                if (numbers1[i] < numbers2[i])
                    return true;
            }

            return false;
        }

        private bool IsSubVersion1LessThanSubVersion2(string mainVersion1, string mainVersion2)
        {
            if (mainVersion1.Length == 0 && mainVersion2.Length > 0)
                return true;

            if (mainVersion1.Length != mainVersion2.Length)
                throw new Exception("Main version string length unmatched.");

            for (int i = 0; i < mainVersion1.Length; i++)
            {
                if ((int)mainVersion1[i] < (int)mainVersion2[i])
                    return true;
            }

            return false;
        }

        public override string ToString()
        {
            return ServiceName + " " + CVE + " " + Description.ToString().PadLeft(4, '0');
        }


        public override bool Equals(object obj)
        {
            if (!(obj is CveDetail))
                return false;

            CveDetail b = (CveDetail)obj;
            if (b.CVE == CVE)
                return true;

            return false;
        }

        public override int GetHashCode()
        {
            return CVE.GetHashCode();
        }

        public static bool operator==(CveDetail a, CveDetail b)
        {
            return a.Equals(b);
        } 

        public static bool operator!=(CveDetail a, CveDetail b)
        {
            return !a.Equals(b);
        }
    }
}

