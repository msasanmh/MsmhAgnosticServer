using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace MsmhToolsClass;

public class TextTool
{
    public async static Task<List<string>> GetLinksAsync(string line)
    {
        List<string> links = new();

        await Task.Run(async () =>
        {
            try
            {
                string find = "://";
                if (line.Contains(find))
                {
                    int start = line.IndexOf(find);
                    int end = start;
                    if (start != -1)
                    {
                        while (true)
                        {
                            start--;
                            if (start != -1)
                            {
                                char startChar = line[start];
                                if (startChar.Equals(' '))
                                {
                                    start++;
                                    break;
                                }
                            }
                            else
                            {
                                start++;
                                break;
                            }
                        }

                        while (true)
                        {
                            end++;
                            if (end < line.Length)
                            {
                                char endChar = line[end];
                                if (endChar.Equals(' ')) break;
                            }
                            else break;
                        }

                        if (end > start)
                        {
                            string link = line[start..end];
                            links.Add(link);
                            line = line.Replace(link, string.Empty);
                            links.AddRange(await GetLinksAsync(line));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("TextTool GetLinks: " + ex.Message);
            }
        });

        return links;
    }

    public static async Task<string> RemoveTextAsync(string text, char startChar, char endChar, bool replaceWithSpace = false)
    {
        await Task.Run(() =>
        {
            if (text.Contains(startChar) && text.Contains(endChar))
            {
                try
                {
                    text = Regex.Replace(text, $"{startChar}.*?{endChar}", " ");

                    while (true)
                    {
                        int start = text.IndexOf(startChar);
                        int end = text.IndexOf(endChar);
                        if (start != -1 && end != -1)
                        {
                            if (end > start)
                            {
                                text = text.Remove(start, end - start + 1);
                                if (replaceWithSpace) text = text.Insert(start, " ");
                            }
                            else text = text.Remove(end, 1);
                        }
                        else break;
                    }
                }
                catch (Exception) { }
            }
        });
        
        return text;
    }

    public static async Task<string> RemoveHtmlTagsAsync(string html, bool replaceTagsWithSpace)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(html)) return string.Empty;

            html = await RemoveTextAsync(html, '<', '>', replaceTagsWithSpace);
            html = await RemoveTextAsync(html, '{', '}', replaceTagsWithSpace);
            
            string[] lines = html.ReplaceLineEndings().Split(Environment.NewLine, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            html = WebUtility.HtmlDecode(lines.ToList().ToString(Environment.NewLine));
        }
        catch (Exception) { }
        return html;
    }

    public static bool IsValidRegex(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return false;

        try
        {
            Regex.Match("", pattern);
        }
        catch (Exception)
        {
            return false;
        }

        return true;
    }
}