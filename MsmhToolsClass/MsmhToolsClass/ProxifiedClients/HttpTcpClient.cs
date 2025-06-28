//
//  Author:
//       Benton Stark <benton.stark@gmail.com>
//
//  Copyright (c) 2016 Benton Stark
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Globalization;
using System.Diagnostics;

namespace MsmhToolsClass.ProxifiedClients;

/// <summary>
/// HTTP connection proxy class.  This class implements the HTTP standard proxy protocol.
/// <para>
/// You can use this class to set up a connection to an HTTP proxy server.  Calling the 
/// CreateConnection() method initiates the proxy connection and returns a standard
/// System.Net.Socks.TcpClient object that can be used as normal. The proxy plumbing
/// is all handled for you.
/// </para>
/// <code>
/// 
/// </code>
/// </summary>
public class HttpTcpClient
{
    private readonly string _proxyHost = IPAddress.Loopback.ToString(); // Default
    private readonly int _proxyPort = 8080; // Default
    private readonly string _proxyUsername = string.Empty;
    private readonly string _proxyPassword = string.Empty;
    private HttpResponseCodes? _respCode;
    private string? _respText;
    private TcpClient? _tcpClient;
    private readonly HttpVersions _httpVersion = HttpVersions.Version1_0;

    private const string HTTP_PROXY_CONNECT_CMD = "CONNECT {0}:{1} HTTP/{2}\r\nHOST: {0}:{1}\r\n\r\n";
    private const string HTTP_PROXY_AUTHENTICATE_CMD = "CONNECT {0}:{1} HTTP/{3}\r\nHOST: {0}:{1}\r\nProxy-Authorization: Basic {2}\r\n\r\n";

    private const int WAIT_FOR_DATA_INTERVAL = 50; // 50 ms
    private const int WAIT_FOR_DATA_TIMEOUT = 15000; // 15 seconds

    /// <summary>
    /// HTTP header version enumeration.
    /// </summary>
    public enum HttpVersions
    {
        /// <summary>
        /// Specify HTTP/1.0 version in HTTP header requests.
        /// </summary>
        Version1_0,
        /// <summary>
        /// Specify HTTP/1.1 version in HTTP header requests.
        /// </summary>
        Version1_1,
    }

    private enum HttpResponseCodes
    {
        None = 0,
        Continue = 100,
        SwitchingProtocols = 101,
        OK = 200,
        Created = 201,
        Accepted = 202,
        NonAuthoritiveInformation = 203,
        NoContent = 204,
        ResetContent = 205,
        PartialContent = 206,
        MultipleChoices = 300,
        MovedPermanetly = 301,
        Found = 302,
        SeeOther = 303,
        NotModified = 304,
        UserProxy = 305,
        TemporaryRedirect = 307,
        BadRequest = 400,
        Unauthorized = 401,
        PaymentRequired = 402,
        Forbidden = 403,
        NotFound = 404,
        MethodNotAllowed = 405,
        NotAcceptable = 406,
        ProxyAuthenticantionRequired = 407,
        RequestTimeout = 408,
        Conflict = 409,
        Gone = 410,
        PreconditionFailed = 411,
        RequestEntityTooLarge = 413,
        RequestURITooLong = 414,
        UnsupportedMediaType = 415,
        RequestedRangeNotSatisfied = 416,
        ExpectationFailed = 417,
        InternalServerError = 500,
        NotImplemented = 501,
        BadGateway = 502,
        ServiceUnavailable = 503,
        GatewayTimeout = 504,
        HTTPVersionNotSupported = 505
    }

    /// <summary>
    /// Constructor.  
    /// </summary>
    /// <param name="proxyHost">Host name or IP address of the proxy server.</param>
    /// <param name="proxyPort">Port number for the proxy server.</param>
    public HttpTcpClient(string proxyHost, int proxyPort)
    {
        if (proxyPort <= 0 || proxyPort > 65535) return;

        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
    }

    /// <summary>
    /// Constructor.  
    /// </summary>
    /// <param name="proxyHost">Host name or IP address of the proxy server.</param>
    /// <param name="proxyPort">Port number to connect to the proxy server.</param>
    /// <param name="proxyUsername">Username for the proxy server.</param>
    /// <param name="proxyPassword">Password for the proxy server.</param>
    public HttpTcpClient(string proxyHost, int proxyPort, string? proxyUsername, string? proxyPassword)
    {
        if (proxyPort <= 0 || proxyPort > 65535) return;

        _proxyHost = proxyHost;
        _proxyPort = proxyPort;

        if (!string.IsNullOrEmpty(proxyUsername))
            _proxyUsername = proxyUsername;

        if (!string.IsNullOrEmpty(proxyPassword))
            _proxyPassword = proxyPassword;
    }

    /// <summary>
    /// Creates a remote TCP connection through a proxy server to the destination host on the destination port.
    /// </summary>
    /// <param name="destinationHost">Destination host name or IP address.</param>
    /// <param name="destinationPort">Port number to connect to on the destination host.</param>
    /// <returns>
    /// Returns an open TcpClient object that can be used normally to communicate
    /// with the destination server
    /// </returns>
    /// <remarks>
    /// This method creates a connection to the proxy server and instructs the proxy server
    /// to make a pass through connection to the specified destination host on the specified
    /// port.  
    /// </remarks>
    public async Task<TcpClient?> CreateConnectionAsync(string destinationHost, int destinationPort)
    {
        try
        {
            if (string.IsNullOrEmpty(destinationHost)) return null;
            if (destinationPort <= 0 || destinationPort > 65535) return null;
            if (string.IsNullOrEmpty(_proxyHost)) return null;
            if (_proxyPort <= 0 || _proxyPort > 65535) return null;

            //  create new tcp client object to the proxy server
            _tcpClient = new TcpClient();

            // attempt to open the connection
            await _tcpClient.ConnectAsync(_proxyHost, _proxyPort);
            
            //  send connection command to proxy host for the specified destination host and port
            bool isSuccess = await SendCommandAsync(destinationHost, destinationPort);
            if (!isSuccess)
            {
                _tcpClient = null;
                return null;
            }

            // remove the private reference to the tcp client so the proxy object does not keep it
            // return the open proxied tcp client object to the caller for normal use
            TcpClient rtn = _tcpClient;
            _tcpClient = null;
            return rtn;
        }
        catch (Exception ex)
        {
            string msg;
            if (_tcpClient == null)
                msg = "Tcp Client is null.";
            else
                msg = $"Connection to proxy {Utils.GetHost(_tcpClient)}:{Utils.GetPort(_tcpClient)} failed.";
            Debug.WriteLine($"{msg}{Environment.NewLine}{ex.Message}");

            return null;
        }
    }


    private async Task<bool> SendCommandAsync(string host, int port)
    {
        bool isSuccess = false;

        try
        {
            if (_tcpClient == null) return isSuccess;

            NetworkStream stream = _tcpClient.GetStream();

            string? connectCmd = CreateCommandString(host, port);
            if (string.IsNullOrEmpty(connectCmd)) return isSuccess;

            byte[] request = Encoding.ASCII.GetBytes(connectCmd);

            // send the connect request
            await stream.WriteAsync(request);

            // wait for the proxy server to respond
            bool isOk = await WaitForDataAsync(stream);
            if (!isOk) return isSuccess;

            // PROXY SERVER RESPONSE
            // =======================================================================
            //HTTP/1.0 200 Connection Established<CR><LF>
            //[.... other HTTP header lines ending with <CR><LF>..
            //ignore all of them]
            //<CR><LF>    // Last Empty Line

            // create an byte response array  
            byte[] response = new byte[_tcpClient.ReceiveBufferSize];
            StringBuilder sbuilder = new();
            int bytes;

            do
            {
                bytes = await stream.ReadAsync(response);
                sbuilder.Append(Encoding.UTF8.GetString(response, 0, bytes));
            }
            while (stream.DataAvailable);

            isOk = ParseResponse(sbuilder.ToString());
            if (!isOk) return isSuccess;

            //  evaluate the reply code for an error condition
            if (_respCode != HttpResponseCodes.OK)
                HandleProxyCommandError(host, port);
            else
                isSuccess = true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine("HttpTcpClient SendCommandAsync: " + ex.Message);
        }

        return isSuccess;
    }

    private string? CreateCommandString(string host, int port)
    {
        string? connectCmd = null;
        try
        {
            if (!string.IsNullOrEmpty(_proxyUsername))
            {
                //  gets the user/pass into base64 encoded string in the form of [username]:[password]
                string auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", _proxyUsername, _proxyPassword)));

                // PROXY SERVER REQUEST
                // =======================================================================
                //CONNECT starksoft.com:443 HTTP/1.0<CR><LF>
                //HOST starksoft.com:443<CR><LF>
                //Proxy-Authorization: username:password<CR><LF>
                //              NOTE: username:password string will be base64 encoded as one 
                //                        concatenated string
                //[... other HTTP header lines ending with <CR><LF> if required]>
                //<CR><LF>    // Last Empty Line
                connectCmd = string.Format(CultureInfo.InvariantCulture, HTTP_PROXY_AUTHENTICATE_CMD,
                    host, port.ToString(CultureInfo.InvariantCulture), auth, GetHttpVersionString());
            }
            else
            {
                // PROXY SERVER REQUEST
                // =======================================================================
                //CONNECT starksoft.com:443 HTTP/1.0 <CR><LF>
                //HOST starksoft.com:443<CR><LF>
                //[... other HTTP header lines ending with <CR><LF> if required]>
                //<CR><LF>    // Last Empty Line
                connectCmd = string.Format(CultureInfo.InvariantCulture, HTTP_PROXY_CONNECT_CMD,
                    host, port.ToString(CultureInfo.InvariantCulture), GetHttpVersionString());
            }
        }
        catch (Exception) { }
        return connectCmd;
    }

    private void HandleProxyCommandError(string host, int port)
    {
        string msg = _respCode switch
        {
            HttpResponseCodes.None => $"Proxy destination {host} on port {port} failed to return a recognized HTTP response code.  Server response: {_respText}",
            HttpResponseCodes.BadGateway => $"Proxy destination {host} on port {port} responded with a 502 code - Bad Gateway.  If you are connecting to a Microsoft ISA destination please refer to knowledge based article Q283284 for more information.  Server response: {_respText}", //HTTP/1.1 502 Proxy Error (The specified Secure Sockets Layer (SSL) port is not allowed. ISA Server is not configured to allow SSL requests from this port. Most Web browsers use port 443 for SSL requests.)
            _ => $"Proxy destination {host} on port {port} responded with a {_respCode} code - {_respText}",
        };

        Debug.WriteLine(msg);
    }

    private static async Task<bool> WaitForDataAsync(NetworkStream stream)
    {
        bool isSuccess = false;

        try
        {
            int sleepTime = 0;
            while (!stream.DataAvailable)
            {
                await Task.Delay(WAIT_FOR_DATA_INTERVAL);
                sleepTime += WAIT_FOR_DATA_INTERVAL;
                if (sleepTime > WAIT_FOR_DATA_TIMEOUT)
                {
                    Debug.WriteLine("Proxy Server didn't respond. Is Stream Data Available: " + stream.DataAvailable);
                    return isSuccess;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("HttpTcpClient WaitForDataAsync: " + ex.Message);
            return isSuccess;
        }

        isSuccess = true;
        return isSuccess;
    }

    private bool ParseResponse(string response)
    {
        bool isSuccess = false;

        try
        {
            string[] data = response.ReplaceLineEndings().Split(Environment.NewLine);
            string line = data[0];

            if (!line.Contains("HTTP", StringComparison.CurrentCulture))
            {
                string msg = $"No HTTP response received from proxy destination.  Server response: {line}.";
                Debug.WriteLine(msg);
                return isSuccess;
            }

            int begin = line.IndexOf(" ") + 1;
            int end = line.IndexOf(" ", begin);

            string val = line[begin..end];

            if (!int.TryParse(val, out int code))
            {
                string msg = $"An invalid response code was received from proxy destination.  Server response: {line}.";
                Debug.WriteLine(msg);
                return isSuccess;
            }

            _respCode = (HttpResponseCodes)code;
            _respText = line[(end + 1)..].Trim();
        }
        catch (Exception ex)
        {
            Debug.WriteLine("HttpTcpClient ParseResponse: " + ex.Message);
            return isSuccess;
        }

        isSuccess = true;
        return isSuccess;
    }

    private string? GetHttpVersionString()
    {
        return _httpVersion switch
        {
            HttpVersions.Version1_0 => "1.0",
            HttpVersions.Version1_1 => "1.1",
            _ => null,
        };
    }

}