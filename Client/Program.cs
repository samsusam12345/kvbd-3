using System;
using System.Threading;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Client
{
    class Program
    {
        static string subject;
        private static string host = "127.0.0.1";
        private static int port = 11000;
        static TcpClient client;
        static NetworkStream stream;
        static List<string> requests = new List<string>();
        static Dictionary<string, byte[]> signDic = new Dictionary<string, byte[]>();
        static X509Certificate2 cert;
        static void Main(string[] args)
        {
            List<string> localCerts = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.pfx").ToList();
            if (localCerts.Count > 0)
            {
                Console.WriteLine("Which certificate to use?");
                foreach (string localCert in localCerts)
                    Console.WriteLine("{0}.{1}", localCerts.IndexOf(localCert), localCert.Remove(0, localCert.LastIndexOf(@"\")+1).Replace(".pfx", String.Empty));
                int index = Convert.ToInt32(Console.ReadLine());
                cert = new X509Certificate2(localCerts[index]);
                subject = cert.Subject.Replace("CN=", String.Empty);
            }
            else
            {
                Console.WriteLine("No certificates found");
                Console.ReadKey();
                return;
            }

            while (true)
            {
                Console.Write("IP: ");
                host = Console.ReadLine();
                Console.Write("PORT: ");
                port = Convert.ToInt32(Console.ReadLine());
                client = new TcpClient();
                try
                {
                    client.Connect(host, port); //подключение клиента
                    stream = client.GetStream(); // получаем поток
                    BinaryFormatter formatter = new BinaryFormatter();
                    Task task = Task.Run(() => ReceiveMessage());
                    Dictionary<string, object> data = new Dictionary<string, object>();
                    data.Add("command", "authReq");
                    data.Add("subject", subject);
                    formatter.Serialize(stream, data);

                    while (true)
                    {
                        string command = Console.ReadLine();
                        data.Clear();
                        switch (command)
                        {


                            default:
                                {
                                    Console.WriteLine("Unknown command");
                                    break;
                                }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    Disconnect();
                }
            }
        }
        // получение сообщений
        static void ReceiveMessage()
        {
            while (true)
            {
                try
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(stream); // буфер для получаемых данных
                    switch ((string)data["command"])
                    {
                        case "authQ":
                            {
                                RSA rsa = (RSA)cert.PrivateKey;
                                byte[] value = (byte[])data["value"];
                                value = rsa.SignData(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                                data["command"] = "authAns";
                                data["value"] = value;
                                formatter.Serialize(stream, data);
                                break;
                            }
                        case "authR":
                            {
                                Console.WriteLine((bool)data["value"] ? "Authentication succeeded" : "Authentication failed");
                                break;
                            }
                        default:
                            {
                                break;
                            }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Подключение прервано!\n{0}\n{1}", e.Message, e.StackTrace); //соединение было прервано
                    Console.ReadLine();
                    Disconnect();
                }
            }
        }

        static void Disconnect()
        {
            if (stream != null)
                stream.Close();//отключение потока
            if (client != null)
                client.Close();//отключение клиента
            Environment.Exit(0); //завершение процесса
        }
    }
}
