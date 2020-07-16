using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace TlsInfo {
    class Program {

        private const int ScreenWidth = 80;

        private const int DefaultPortNumber = 443;

        private const string Localhost = "localhost";

        private static readonly Regex s_hostNameWithPort = new Regex(@"^(?<host>.+):(?<port>\d+)$");


        static async Task Main(string[] args) {
            if (args.Length == 0) {
                Console.WriteLine("No host names specified!");
            }

            foreach (var hostName in args) {
                Console.WriteLine();
                WriteLineWithColour(GetHeader(hostName), ConsoleColor.DarkGreen);
                Console.WriteLine();
                
                try {
                    string host;
                    var port = DefaultPortNumber;

                    var m = s_hostNameWithPort.Match(hostName);
                    if (m.Success) {
                        host = m.Groups["host"].Value;
                        port = int.Parse(m.Groups["port"].Value);
                    }
                    else {
                        host = hostName;
                    }

                    string resolvedHostNameOrIp;

                    if (IPAddress.TryParse(host, out var ip)) {
                        resolvedHostNameOrIp = ip.ToString();
                    }
                    else if (string.Equals(host, Localhost, StringComparison.OrdinalIgnoreCase)) {
                        resolvedHostNameOrIp = Localhost;
                    }
                    else {
                        var dnsEntry = await Dns.GetHostEntryAsync(host).ConfigureAwait(false);
                        resolvedHostNameOrIp = dnsEntry.HostName;
                    }
                    
                    Console.WriteLine($"Resolved Host Name: {resolvedHostNameOrIp}");
                    
                    using (var tcpClient = new TcpClient(resolvedHostNameOrIp, port))
                    using (var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate, null)) {
                        await sslStream.AuthenticateAsClientAsync(
                            resolvedHostNameOrIp,
                            null,
                            SslProtocols.Tls12,
                            true
                        ).ConfigureAwait(false);

                        var tlsInfo = new TlsInfo(sslStream);
                        Console.WriteLine($"TLS Version: {tlsInfo.ProtocolVersion}");
                        Console.WriteLine($"Key Exchange Algorithm: {tlsInfo.KeyExchangeAlgorithm}");
                        Console.WriteLine($"Cipher Algorithm: {tlsInfo.CipherAlgorithm}");
                        Console.WriteLine($"Hash Algorithm: {tlsInfo.HashAlgorithm}");
                        Console.WriteLine("Certificate:");
                        Console.WriteLine();
                        Console.WriteLine(tlsInfo.RemoteCertificate.ToString(false));
                    }
                }
                catch (Exception e) {
                    WriteLineWithColour(e.ToString(), ConsoleColor.DarkRed);
                    Console.WriteLine();
                }
            }
        }


        private static string GetHeader(string hostName) {
            var result = new StringBuilder();

            var padding = (ScreenWidth - hostName.Length - 2) / 2;

            if (padding > 0) {
                result.Append(Enumerable.Repeat('=', padding).ToArray());
                result.Append(' ');
            }
            result.Append(hostName);
            if (padding > 0) {
                result.Append(' ');
                result.Append(Enumerable.Repeat('=', padding).ToArray());
            }

            return result.ToString();
        }


        private static bool ValidateServerCertificate(
            object sender,
            X509Certificate cert,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        ) {
            if (sslPolicyErrors != SslPolicyErrors.None) {
                WriteLineWithColour($"SSL Policy Error: {sslPolicyErrors}", ConsoleColor.DarkYellow);
            }
            return true;
        }


        private static void WriteLineWithColour(string message, ConsoleColor colour) {
            var currentColour = Console.ForegroundColor;
            Console.ForegroundColor = colour;
            Console.WriteLine(message);
            Console.ForegroundColor = currentColour;
        }


        public enum KeyExchangeAlgorithmType {
            /// <summary>
            /// No key exchange algorithm is used.
            /// </summary> 
            None = 0,
            /// <summary>
            /// The RSA public-key signature algorithm.
            /// </summary> 
            RsaSign = 9216,
            /// The RSA public-key exchange algorithm.
            /// </summary> 
            RsaKeyX = 41984,
            /// <summary>
            /// The Diffie Hellman ephemeral key exchange algorithm.
            /// </summary> 
            DiffieHellman = 43522,
            /// <summary>
            /// The elliptical curve Diffie Hellman ephemeral key exchange algorithm.
            /// </summary> 
            Ecdhe = 44550
        }


        public class TlsInfo {

            public SslProtocols ProtocolVersion { get; set; }
            public KeyExchangeAlgorithmType KeyExchangeAlgorithm { get; set; }
            public CipherAlgorithmType CipherAlgorithm { get; set; }
            public HashAlgorithmType HashAlgorithm { get; set; }
            public X509Certificate2 RemoteCertificate { get; set; }
            
            public TlsInfo(SslStream SecureStream) {
                ProtocolVersion = SecureStream.SslProtocol;
                KeyExchangeAlgorithm = (KeyExchangeAlgorithmType)SecureStream.KeyExchangeAlgorithm;
                CipherAlgorithm = SecureStream.CipherAlgorithm;
                HashAlgorithm = SecureStream.HashAlgorithm;
                RemoteCertificate = new X509Certificate2(SecureStream.RemoteCertificate);
            }
            
        }


    }
    
}
