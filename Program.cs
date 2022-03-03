using System;
using System.Collections.Generic;
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

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace TlsInfo {
    class Program {

        private const int ScreenWidth = 80;

        private const int DefaultPortNumber = 443;

        private const string Localhost = "localhost";

        private static readonly Regex s_hostNameWithPort = new Regex(@"^(?<host>.+):(?<port>\d+)$");


        static async Task Main(string[] args) {
            Console.WriteLine();

#if NETCOREAPP
            WriteLineWithColour($"[tls-info ({System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription})]", ConsoleColor.DarkGreen);
#else
            var attr = (System.Runtime.Versioning.TargetFrameworkAttribute) System.Reflection.Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(System.Runtime.Versioning.TargetFrameworkAttribute), false).FirstOrDefault();
            WriteLineWithColour($"[tls-info ({attr?.FrameworkDisplayName ?? System.Runtime.InteropServices.RuntimeEnvironment.GetSystemVersion()})]", ConsoleColor.DarkGreen);
#endif
            Console.WriteLine();

            if (args.Length == 0) {
                Console.WriteLine("No host names specified!");
                return;
            }

            var results = new HostResultDictionary();

            try {

                foreach (var hostName in args) {
                    var tlsResults = new TlsResultDictionary();
                    results[hostName] = tlsResults;

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

                    tlsResults.ResolvedHostName = resolvedHostNameOrIp;

                    var tlsVersions = new[] { 
#if NETCOREAPP || NET48_OR_GREATER
                        SslProtocols.Tls13,
#endif
                        SslProtocols.Tls12,
                        SslProtocols.Tls11,
                        SslProtocols.Tls
                    };

                    foreach (var tlsVersion in tlsVersions) {
                        try {
                            using (var tcpClient = new TcpClient(host, port))
                            using (var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate, null)) {
                                await sslStream.AuthenticateAsClientAsync(
                                    host,
                                    null,
                                    tlsVersion,
                                    true
                                ).ConfigureAwait(false);

                                var cert = new X509Certificate2(sslStream.RemoteCertificate);

                                string publicKeyAlg;
#if NET452
                                var publicKeyOid = Oid.FromOidValue(cert.GetKeyAlgorithm(), OidGroup.PublicKeyAlgorithm);
                                publicKeyAlg = publicKeyOid.FriendlyName;
#else
                                try {
                                    var rsa = cert.GetRSAPublicKey();
                                    publicKeyAlg = string.Concat("RSA (", rsa.KeySize, " bits)");
                                    
                                }
                                catch {
                                    var ecdsa = cert.GetECDsaPublicKey();
#if NET472_OR_GREATER || NETCOREAPP
                                    var ecParams = ecdsa.ExportParameters(false);
                                    publicKeyAlg = string.Concat("ECC (", ecParams.Curve.Oid.FriendlyName ?? ecParams.Curve.Oid.Value, "; ", ecdsa.KeySize, " bits)");
#else
                                    publicKeyAlg = string.Concat("ECC (", ecdsa.KeySize, " bits)");
#endif
                                }
#endif

                                    tlsResults.Results[tlsVersion] = new TlsResult() {
                                    CipherAlgorithm = sslStream.CipherAlgorithm,
                                    HashAlgorithm = sslStream.HashAlgorithm,
                                    KeyExchangeAlgorithm = (KeyExchangeAlgorithmType) sslStream.KeyExchangeAlgorithm,
                                    Certificate = new X509CertificateInfo() {
                                        Issuer = cert.Issuer,
                                        PublicKeyAlgorithm = publicKeyAlg,
                                        NotAfter = cert.GetExpirationDateString(),
                                        NotBefore = cert.GetEffectiveDateString(),
                                        SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName ?? cert.SignatureAlgorithm?.Value,
                                        Subject = cert.Subject,
                                        Thumbprint = cert.GetCertHashString()
                                    }
                                };
                            }
                        }
                        catch (Exception e) {
                            var errors = new List<string>();
                            do {
                                errors.Add(e.Message);
                                e = e.InnerException;
                            } while (e != null);
                            tlsResults.Results[tlsVersion] = new { Errors = errors.ToArray() };
                        }
                    }

                }

                Console.WriteLine(JsonConvert.SerializeObject(results, Formatting.Indented, new StringEnumConverter()));
            }
            catch (Exception e) {
                WriteLineWithColour(e.ToString(), ConsoleColor.DarkRed);
                return;
            }
        }


        private static bool ValidateServerCertificate(
            object sender,
            X509Certificate cert,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        ) {
            //if (sslPolicyErrors != SslPolicyErrors.None) {
            //    WriteLineWithColour($"SSL Policy Error: {sslPolicyErrors}", ConsoleColor.DarkYellow);
            //}
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


        public class HostResultDictionary : Dictionary<string, TlsResultDictionary> {

            public HostResultDictionary() : base(StringComparer.OrdinalIgnoreCase) { }

        }


        public class TlsResultDictionary {
            public string ResolvedHostName { get; set; }
            public IDictionary<SslProtocols, object> Results { get; } = new Dictionary<SslProtocols, object>();
        }


        public class TlsResult {
            public KeyExchangeAlgorithmType KeyExchangeAlgorithm { get; set; }
            public CipherAlgorithmType CipherAlgorithm { get; set; }
            public HashAlgorithmType HashAlgorithm { get; set; }
            public X509CertificateInfo Certificate { get; set; }
        }


        public class X509CertificateInfo {
            public string Subject { get; set; }
            public string Issuer { get; set; }
            public string NotBefore { get; set; }
            public string NotAfter { get; set; }
            public string PublicKeyAlgorithm { get; set; }
            public string SignatureAlgorithm { get; set; }
            public string Thumbprint { get; set; }
        }


    }
    
}
