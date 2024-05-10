﻿using System.Diagnostics;

namespace MsmhToolsClass.MsmhAgnosticServer;

public partial class AgnosticProgram
{
    public static class Rules
    {
        public readonly struct KEYS
        {
            public static readonly string FirstKey = "FirstKey";
            public static readonly string AllClients = "AllClients";
            public static readonly string BlockPort = "blockport:";
            public static readonly string Dns = "dns:";
            public static readonly string DnsDomain = "dnsdomain:";
            public static readonly string DnsProxy = "dnsproxy:";
            public static readonly string Sni = "sni:";
            public static readonly string Proxy = "proxy:";
        }

        public readonly struct SUB_KEYS
        {
            public static readonly string FirstKey = "FirstKey";
            public static readonly string IfBlock = "&ifblock:";
            public static readonly string User = "&user:";
            public static readonly string Pass = "&pass:";
        }

        public static string GetValue(string line, string key, string? subKey, out bool isList, out List<string> list, List<Tuple<string, string>> variables)
        {
            string result = line.Trim();
            isList = false;
            list = new();

            try
            {
                if (result.Contains(key, StringComparison.InvariantCultureIgnoreCase) || key == KEYS.FirstKey)
                {
                    try
                    {
                        if (key == KEYS.FirstKey)
                        {
                            result = result.Remove(result.IndexOf(';'));
                            result = result.Trim();
                        }
                        else
                        {
                            result = result.Remove(0, result.IndexOf(key, StringComparison.InvariantCultureIgnoreCase) + key.Length);
                            result = result.Remove(result.IndexOf(';'));
                            result = result.Trim();
                        }
                    }
                    catch (Exception) { }

                    if (!string.IsNullOrEmpty(subKey))
                    {
                        if (subKey.Equals(SUB_KEYS.FirstKey, StringComparison.InvariantCultureIgnoreCase))
                        {
                            if (result.Contains('&'))
                            {
                                try
                                {
                                    result = result.Remove(result.IndexOf('&'));
                                }
                                catch (Exception) { }
                            }
                        }
                        else
                        {
                            if (result.Contains(subKey, StringComparison.InvariantCultureIgnoreCase))
                            {
                                try
                                {
                                    result = result.Remove(0, result.IndexOf(subKey, StringComparison.InvariantCultureIgnoreCase) + subKey.Length);
                                }
                                catch (Exception) { }

                                if (result.Contains('&') && result.Contains(':'))
                                {
                                    try
                                    {
                                        result = result.Remove(result.IndexOf('&'));
                                    }
                                    catch (Exception) { }
                                }
                            }
                        }
                    }

                    if (!result.Contains(','))
                    {
                        // Not A List
                        return ApplyVariables(result, variables);
                    }
                    else
                    {
                        // It's A List
                        isList = true;
                        string[] split = result.Split(',');
                        for (int n = 0; n < split.Length; n++)
                        {
                            string value = split[n].Trim();
                            list.Add(ApplyVariables(value, variables));
                        }
                        if (list.Any()) return list[0];
                    }
                }
            }
            catch (Exception) { }

            return string.Empty;
        }

        private static string ApplyVariables(string vari, List<Tuple<string, string>> variables)
        {
            string result = vari;
            try
            {
                variables = variables.ToList();
                for (int n = 0; n < variables.Count; n++)
                {
                    Tuple<string, string> tuple = variables[n];
                    if (vari.Equals(tuple.Item1))
                    {
                        result = tuple.Item2; break;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Rules_ApplyVariables: " + ex.Message);
            }
            return result;
        }

        public static bool IsDomainMatch(string host, string ruleHost, out bool isWildcard, out string hostNoWWW, out string ruleHostNoWWW)
        {
            isWildcard = false;
            hostNoWWW = host.ToLower().Trim();
            ruleHostNoWWW = ruleHost.ToLower().Trim();

            try
            {
                if (hostNoWWW.StartsWith("www."))
                    hostNoWWW = hostNoWWW.TrimStart("www.");
                if (hostNoWWW.EndsWith('/')) hostNoWWW = hostNoWWW[0..^1];

                if (ruleHostNoWWW.StartsWith("www."))
                    ruleHostNoWWW = ruleHostNoWWW.TrimStart("www.");
                if (ruleHostNoWWW.EndsWith('/')) ruleHostNoWWW = ruleHostNoWWW[0..^1];

                if (!string.IsNullOrEmpty(ruleHostNoWWW))
                {
                    if (ruleHostNoWWW.Equals("*")) return true; // No Wildcard

                    if (!ruleHostNoWWW.StartsWith("*."))
                    {
                        // No Wildcard
                        if (ruleHostNoWWW.Equals(hostNoWWW)) return true;
                    }
                    else
                    {
                        // Wildcard
                        isWildcard = true;
                        if (!hostNoWWW.Equals(ruleHostNoWWW[2..]) && hostNoWWW.EndsWith(ruleHostNoWWW[1..])) return true;
                    }
                }
            }
            catch (Exception) { }

            return false;
        }
    }
}