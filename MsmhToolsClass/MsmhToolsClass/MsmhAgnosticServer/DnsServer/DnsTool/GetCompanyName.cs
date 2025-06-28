﻿using System.Diagnostics;

namespace MsmhToolsClass.MsmhAgnosticServer;

public static class GetCompanyName
{
    public static string HostToCompanyOffline(string host, string fileContent)
    {
        host = host.Trim();
        string company = string.Empty;
        if (!string.IsNullOrWhiteSpace(host))
        {
            if (!string.IsNullOrWhiteSpace(fileContent))
            {
                List<string> split = fileContent.SplitToLines();
                for (int n = 0; n < split.Count; n++)
                {
                    string hostToCom = split[n];
                    if (hostToCom.Contains(host) && hostToCom.Contains('|'))
                    {
                        string com = hostToCom.Split('|')[1];
                        if (!string.IsNullOrWhiteSpace(com))
                        {
                            company = com;
                            break;
                        }
                    }
                }
            }
        }
        return company.Trim();
    }

    public static string UrlToCompanyOffline(string url, string fileContent)
    {
        NetworkTool.URL urid = NetworkTool.GetUrlOrDomainDetails(url, 53);
        return HostToCompanyOffline(urid.Host, fileContent);
    }

    public static string StampToCompanyOffline(string stampUrl, string fileContent)
    {
        stampUrl = stampUrl.Trim();
        string company = "Couldn't retrieve information.";
        // Can't always return Address
        try
        {
            // Decode Stamp
            DNSCryptStampReader stamp = new(stampUrl);

            if (!string.IsNullOrEmpty(stamp.Host))
                company = HostToCompanyOffline(stamp.Host, fileContent);
            else if (!string.IsNullOrEmpty(stamp.IP.ToString()))
                company = HostToCompanyOffline(stamp.IP.ToString(), fileContent);
            else
                company = HostToCompanyOffline(stampUrl, fileContent);
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex.Message);
        }

        return company;
    }
}

