using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Program
    {
        public class PrefixedWriter : TextWriter
        {
            private TextWriter originalOut;

            public PrefixedWriter()
            {
                originalOut = Console.Out;
            }

            public override Encoding Encoding
            {
                get { return new System.Text.ASCIIEncoding(); }
            }
            public override void WriteLine(string message)
            {
                originalOut.WriteLine(String.Format("[{0}] {1}", DateTime.Now, message));
            }
            public override void Write(string message)
            {
                originalOut.Write(String.Format("[{0}] {1}", DateTime.Now, message));
            }
        }

        static X509Certificate2 rootCert;
        static ServerObject server;
        static Task listenTask;
        static void Main(string[] args)
        {
            Console.SetOut(new PrefixedWriter());
            Console.WriteLine("Server is starting");
            Console.WriteLine("Trying to upload root certificate");
            if (File.Exists("root.pfx"))
            {
                rootCert = new X509Certificate2("root.pfx");
                Console.WriteLine("Certificate uploaded");
            }
            else
            {
                Console.WriteLine("Root certificate was not found.");
                Console.Write("Enter the name of the holder: ");
                string subjectName = Console.ReadLine();
                Console.Write("Enter the amount of years for the certificate to expire: ");
                string expirate = Console.ReadLine();
                foreach (char c in expirate)
                    if (!Char.IsDigit(c))
                        expirate = expirate.Replace(c.ToString(), "");
                if (createRootCert(subjectName, DateTimeOffset.Now.AddYears(Convert.ToInt32(expirate))))
                {
                    Console.WriteLine("Certificate has been successfully created!");
                    rootCert = new X509Certificate2("root.pfx");
                    Console.WriteLine("Certificate uploaded");
                }
                else
                {
                    Console.WriteLine("Shutting down server...");
                    Console.ReadKey();
                    return;
                }
            }
            Console.WriteLine("Type \"help\" to get the information on existing commands");

            try
            {
                server = new ServerObject();
                listenTask = Task.Run(() => server.Listen());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                server.Disconnect();
            }

            while (true)
            {
                string command = Console.ReadLine();
                switch (command)
                {
                    case "help":
                        Console.WriteLine("crtCreate - creates a new certificate with th specified values and a private key");
                        Console.WriteLine("quit - shuts down the server");
                        break;

                    case "crtCreate":
                        {
                            Console.Write("Enter the name of the holder: ");
                            string subjectName = Console.ReadLine();
                            Console.Write("Enter the amount of years for the certificate to expire: ");
                            string expirate = Console.ReadLine();
                            foreach (char c in expirate)
                                if (!Char.IsDigit(c))
                                    expirate = expirate.Replace(c.ToString(), "");
                            Console.WriteLine(createChildCert(subjectName, DateTimeOffset.Now.AddYears(Convert.ToInt32(expirate)))? $"Certificate for {subjectName} has been successfully created." : $"Couldn't create a certificate for {subjectName}.");
                        }
                        break;

                    case "showConnections":
                        {
                            Console.WriteLine("You have {0} connections", ServerObject.clients.Count);
                            for (int i = 1; i <= ServerObject.clients.Count; i++)
                                Console.WriteLine("{0}.{1}", i, ServerObject.clients[i-1].userName);
                            break;
                        }
                    case "removeConnection":
                        {
                            Console.WriteLine("You have {0} connections", ServerObject.clients.Count);
                            for (int i = 1; i <= ServerObject.clients.Count; i++)
                                Console.WriteLine("{0}.{1}", i, ServerObject.clients[i - 1].userName);
                            Console.Write("Connection to remove: ");
                            int index = Convert.ToInt32(Console.ReadLine());
                            ServerObject.clients[index - 1].Close();
                            Console.WriteLine("Connection removed");
                            break;
                        }
                    case "quit":
                        Console.WriteLine("Shutting down the server...");
                        Console.ReadKey();
                        return;

                    default:
                        Console.WriteLine("Unknown command");
                        break;
                }
            }
        }

        static bool createRootCert(string subjectName, DateTimeOffset expirate)
        {
            try
            {
                Console.WriteLine("Creating root certificate...");
                var rsaKey = RSA.Create(2048);
                string subject = "CN=" + subjectName;
                var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
                var caCert = certReq.CreateSelfSigned(DateTimeOffset.Now, expirate);

                File.WriteAllBytes("root.pfx", caCert.Export(X509ContentType.Pfx));

                /* Создание .crt и .key
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(caCert.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                File.WriteAllText($"root.crt", builder.ToString());
                RSA keyCA = (RSA)caCert.PrivateKey;
                string name = keyCA.SignatureAlgorithm.ToUpper();
                builder.Clear();
                builder.AppendLine($"-----BEGIN {name} PRIVATE KEY-----");
                builder.AppendLine(Convert.ToBase64String(keyCA.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine($"-----END {name} PRIVATE KEY-----");
                File.WriteAllText($"root.key", builder.ToString());
                */
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred during creating a root cerificate.\n + {e.Message}");
                return false;
            }
        }

        static bool createChildCert(string subjectName, DateTimeOffset expirate)
        {
           
            try
            {
                Console.WriteLine($"Creating certificate for {subjectName}");
                var clientKey = RSA.Create(2048);
                string clientSubject = $"CN={subjectName}";
                var clientReq = new CertificateRequest(clientSubject, clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                clientReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                clientReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
                clientReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(clientReq.PublicKey, false));
                byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());
                //var clientCert = clientReq.Create(rootCert, DateTimeOffset.Now, expirate, serialNumber);
                var clientCert = clientReq.Create(rootCert, DateTimeOffset.Now, expirate, serialNumber);
                clientCert = clientCert.CopyWithPrivateKey(clientKey);



                File.WriteAllBytes($"{subjectName}.pfx", clientCert.Export(X509ContentType.Pfx));
                // Создание .crt и .key
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(clientCert.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                File.WriteAllText($"{subjectName}.crt", builder.ToString());
                builder.Clear();
                /*
                string name = clientKey.SignatureAlgorithm.ToUpper();
                builder.AppendLine($"-----BEGIN {name} PRIVATE KEY-----");
                builder.AppendLine(Convert.ToBase64String(clientKey.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine($"-----END {name} PRIVATE KEY-----");
                File.WriteAllText($"{subjectName}.key", builder.ToString());
                */

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred during creating a cerificate for {subjectName}.\n + {e.Message}");
                return false;
            }
        }
    }
}
