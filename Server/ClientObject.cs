using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Server
{
    public class ClientObject
    {
        protected internal string Id { get; private set; }
        protected internal NetworkStream Stream { get; private set; }
        protected internal string userName;
        TcpClient client;
        X509Certificate2 cert;
        ServerObject server; // объект сервера
        byte[] authQ;
        bool is_Auth = false;

        public ClientObject(TcpClient tcpClient, ServerObject serverObject)
        {
            Id = Guid.NewGuid().ToString();
            client = tcpClient;
            server = serverObject;
            serverObject.AddConnection(this);
            byte[] rnd = new byte[512];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(rnd);
            authQ = rnd;
        }

        public void Process()
        {
            try
            {
                string message;
                Stream = client.GetStream();
                BinaryFormatter formatter = new BinaryFormatter();

                while (true)
                {
                    try
                    {
                        Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(Stream);
                        switch ((string)data["command"])
                        {
                            case "authReq":
                                {
                                    cert = new X509Certificate2($"{(string)data["subject"]}.crt");
                                    this.userName = (string)data["subject"];
                                    data.Clear();
                                    data.Add("command", "authQ");
                                    data.Add("value", authQ);
                                    formatter.Serialize(Stream, data);
                                    break;
                                }

                            case "authAns":
                                {
                                    bool authAns;
                                    using (RSA rsa = cert.GetRSAPublicKey())
                                    {
                                        authAns = rsa.VerifyData(authQ, (byte[])data["value"], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                                    }
                                    data.Clear();
                                    data.Add("command", "authR");
                                    data.Add("value", authAns);
                                    formatter.Serialize(Stream, data);
                                    if (!authAns)
                                    {
                                        Console.WriteLine("{0} tried to connect but couldn't complete authentication", this.userName);
                                        this.Close();
                                    }
                                    else
                                    {
                                        Console.WriteLine("{0} connected and completed authentication", this.userName);
                                    }
                                    break;
                                }
                            default:
                                {
                                    Console.WriteLine("Unknown command...");
                                    break;
                                }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message + "\n" + e.StackTrace);
            }
            finally
            {
                server.RemoveConnection(this.Id);
                Close();
            }
        }
        // закрытие подключения
        protected internal void Close()
        {
            if (Stream != null)
                Stream.Close();
            if (client != null)
                client.Close();
        }
    }
}
