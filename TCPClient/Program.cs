using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Runtime.InteropServices;

namespace TCPClient
{

    public class TCPClient
    {
        private Socket socketClient = null;
        private Thread threadClient = null;

        private bool _isEnable;
        public bool IsEnable
        {
            get { return _isEnable; }
            set { _isEnable = value; }
        }

        public TCPClient(bool isEnable)
        {
            _isEnable = isEnable;
        }
        public void startClient()
        {
            //连接服务器
            socketClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            if (socketClient == null)
            {
                Console.WriteLine("Create client socket failed !");
                Console.WriteLine("Press any key to exit!");
                Console.ReadKey();
                return;
            }

            //设置要连接的服务器信息（IP和port）
            IPAddress ipaddress = GetLocalIPv4Address();
            IPEndPoint endpoint = new IPEndPoint(ipaddress, 8888);

            try
            {
                socketClient.Connect(endpoint);
                Console.WriteLine("成功连接服务器端: " + socketClient.RemoteEndPoint.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.ToString());
                Console.WriteLine("Press any key to exit!");
                Console.ReadKey();
                return;
            }

            //循环从控制台读入信息，如果输入不是“Exit”，则将信息发送给Server，否则退出
            while (true)
            {
                try
                {
                    string inputMsg = Console.ReadLine();
                    if (inputMsg.Equals("Exit"))
                    {
                        //退出while(true)循环
                        break;
                    }
                    else
                    {
                        //向Server发送inputMsg
                        if (0 != ClientSendMsg(inputMsg))
                        {
                            Console.WriteLine("Failed to send message to server: " + inputMsg);
                            break;
                        }
                        else
                        {
                            //Console.WriteLine("Message sent to server: " + inputMsg);
                            Console.WriteLine("Please input the message:");
                        }
                    }
                }catch(Exception ex)
                {
                    Console.WriteLine("Error: " + ex.ToString());
                    break;
                }
            }
            if(socketClient != null)
            {
                socketClient.Shutdown(SocketShutdown.Both);
                socketClient.Close();
                socketClient = null;
            }
        }

        private int listenServer()
        {
            int ret = 0;
            socketClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            if(socketClient == null)
            {
                Console.WriteLine("Create client socket failed !");
                ret = -1;
            }

            //设置要连接的服务器信息（IP和port）
            IPAddress ipaddress = GetLocalIPv4Address();
            IPEndPoint endpoint = new IPEndPoint(ipaddress,8888);

            try 
            {
                socketClient.Connect(endpoint);
                Console.WriteLine("客户端连接服务器端成功: " + socketClient.RemoteEndPoint.ToString());
                ThreadStart ts = new ThreadStart(RecvMsg);
                threadClient = new Thread(ts);
                threadClient.IsBackground = true;
                threadClient.Start();
            }catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.ToString());
                ret = -1;
            }

            return ret;
        }

        private int ClientSendMsg(string message)
        {
            int ret = 0;
            try
            {
                byte[] arrClientSendMsg = Encoding.UTF8.GetBytes(message);
                socketClient.Send(arrClientSendMsg);
                Console.WriteLine("Client sent \"" + message + "\" to " + socketClient.RemoteEndPoint.ToString() + " at " +  GetCurrentTime());
            }catch(Exception ex)
            {
                Console.WriteLine("Error(in ClientSendMsg()):" + ex.ToString());
                ret = -1;
            }

            return ret;
        }
        private void RecvMsg()
        {
            while(true)
            {
                try
                {
                    byte[] arrRecvMsg = new byte[1024 * 1024];
                    int length = socketClient.Receive(arrRecvMsg);
                    string strRecvMsg = Encoding.UTF8.GetString(arrRecvMsg, 0, length);
                    Console.WriteLine("Recieved message from server: " + strRecvMsg);
                }catch(Exception ex)
                {
                    Console.WriteLine("Error(in RecvMsg()):" + ex.ToString());
                    Console.WriteLine("远程服务器已中断连接！");
                    break;
                }
            }
        }
        private DateTime GetCurrentTime()
        {
            DateTime currentTime = new DateTime();

            currentTime = DateTime.Now;

            return currentTime;
        }
        private IPAddress GetLocalIPv4Address()
        {
            IPAddress localIPv4 = null;

            IPAddress[] IPList = Dns.GetHostAddresses(Dns.GetHostName());

            foreach (IPAddress IP in IPList)
            {
                if (IP.AddressFamily == AddressFamily.InterNetwork)
                {
                    localIPv4 = IP;
                    Console.WriteLine("Current IPv4 is " + localIPv4.ToString());
                }
                else
                {
                    continue;
                }
            }
            return localIPv4;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class param
    {
        public int a;
        public int b;
        public int[] cArray;
        public int[] cArray2;
        public string dStr;
    }
    [StructLayout(LayoutKind.Explicit)]
    public class MEMSPara
    {
        [FieldOffset(0)]
        public byte PowerState;
        [FieldOffset(1)]
        public byte Points;
        [FieldOffset(2)]
        public byte Scale;
        [FieldOffset(3)]
        public ushort SampleRate;
        [FieldOffset(5)]
        public float Res;
        [FieldOffset(9)]
        public byte ChannelNum;
        [FieldOffset(10)]
        public byte PointBytes;
    }

    [StructLayout(LayoutKind.Explicit)]
    public class EEGPara
    {
        [FieldOffset(0)]
        public byte Gain;
        [FieldOffset(1)]
        public byte WorkMode;
        [FieldOffset(2)]
        public ushort ChannelNum;
        [FieldOffset(4)]
        public ushort SampleRate;
        [FieldOffset(6)]
        public byte Points;
    }

    [StructLayout(LayoutKind.Explicit)]
    public class PromptPara
    {
        [FieldOffset(0)]
        public byte PromptType;
        [FieldOffset(2)]
        public ushort Cycle;
        [FieldOffset(3)]
        public byte Times;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CommandData
    {
        public MEMSPara MEMSPara { get; set; }
        public EEGPara EEGPara { get; set; }
        public PromptPara PromptPara { get; set; }
        public int SyncCode { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CommandData2
    {
        public MEMSPara MEMSPara { get; set; }
        public EEGPara EEGPara { get; set; }
        public PromptPara PromptPara { get; set; }
        public int SyncCode { get; set; }
    }
    public class UDPController
    {
        public static void SendBroadcastMsg(byte[] message, int port)
        {
            Socket sendSocket;
            sendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            string hostName = Dns.GetHostName();
            IPAddress[] addressList = Dns.GetHostAddresses(hostName);
            foreach (IPAddress ip in addressList)
            {
                if (ip.AddressFamily != AddressFamily.InterNetwork) //Address for IP version 4
                {
                    continue;
                }
                //ip.Address |= 0xFF000000; //将最后一节换成255，变成广播地址
                IPEndPoint ep = new IPEndPoint(ip, port);
                sendSocket.SendTo(message, ep);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class BoardFlag
    {
        public UInt32 Flag;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class CpuFlag
    {
        public UInt16 Flag;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class CommunicationAddr
    {
        public BoardFlag board;
        public CpuFlag cpu;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class FrameHeader
    {
        public UInt16 Token; //0x0FF0 2bytes
        public UInt16 PayloadLength; //    2bytes
        public UInt16 PackageType;  // 0x0005 2bytes
        /*
         * switch(PackageType)
         * case Command:
         *   SubPackageType = CommandSubHeader.CommandType
         *   PackageSeq     = CommandSubHeader.CommandSequence
         * case BroadCastCommand:
         *   SubPackageType = BroadcastCommandSubHeader.BroadCastCommandType
         *   PackageSeq     = BroadcastCommandSubHeader.CommandSequence
         * case Notification:
         *   SubPackageType = NotificationSubHeader.NotificationType
         * case Alert:
         *   SubPackageType = AlertSubHeader.AlertType
         *   PackageID      = AlertSubHeader.PacketID
         *   
         */
        public UInt16 SubPackageType; // 0x0002 2bytes
        public byte PackageID;        // 0x00 1byte
        public byte PackageSeq;       // 0x00 1byte
        public UInt16 ModuleType;     // 0x0002 2bytes
        public byte Result;           // 0x00 1byte
        public byte ErrorCode;        // 0x00 1byte
        public UInt32 Timestamp;      // 0x00000000 4bytes
        public UInt32 TimestampFPO;   // 0x00000000 4bytes
        public CommunicationAddr SourceAddress;     // 0x000000000000 6bytes
        public CommunicationAddr DestinationAddress; // 0x000000000000 6bytes
    }

    [StructLayout(LayoutKind.Explicit)]
    public class FrameTail
    {
        [FieldOffset(0)]
        public ushort CRC;
        [FieldOffset(2)]
        public ushort TailToken;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class BaseFrame
    {
        public FrameHeader Header;
        public FrameTail Tail;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class BroadcastCommandData
    {
        public int SyncCode;
        public DeviceInfo DeviceInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class MdcpBroadcastCommand : BaseFrame
    {
        public BroadcastCommandData BroadcastData;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public class myByte
    {
        [FieldOffset(0)]
        public byte oneByte;
    }

    [StructLayout(LayoutKind.Explicit, Pack =1)]
    public class DeviceInfo
    {
        [FieldOffset(0)]
        public byte MajorAcpVersion;
        [FieldOffset(1)]
        public byte MinorAcpVersion;
        [FieldOffset(2)]
        public uint SerialNumber;
        [FieldOffset(6)]
        public byte HardwareVersion;
        [FieldOffset(7)]
        public byte FirmwareVersion;
        [FieldOffset(8)]
        public byte FirmwareVersion2;
        [FieldOffset(9)] [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12,ArraySubType =UnmanagedType.U4)]
        public uint[] DeviceType = new uint[12];
    }

    [StructLayout(LayoutKind.Sequential)]
    public class MyPoint
    {
        public int x;
        public int y;
    }

    public class Human
    {
        public string name;
        public int age;

        public Human(string name, int age)
        {
            this.name = name;
            this.age = age;
        }
    }

    public class Car
    {
        public string brand;
        public int price;

        public Car(string brand, int price)
        {
            this.brand = brand;
            this.price = price;
        }
    }


    public abstract class Parent
    {
        public abstract void Dump(object arg);
    }

    public class Child1 : Parent
    {
        public override void Dump(object arg)
        {
            if(arg!=null && arg.GetType() == typeof(Human))
            {
                object temp = arg;
                Human h = (Human)temp;

                Console.WriteLine($"name is {h.name} and age is {h.age}");
            }
        }
    }

    public class Child2 : Parent
    {
        public override void Dump(object arg)
        {
            if (arg != null && arg.GetType() == typeof(Car))
            {
                object temp = arg;
                Car c = (Car)temp;

                Console.WriteLine($"brand is {c.brand} and price is {c.price}");
            }
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            #region
            //TCPClient tcpClient = new TCPClient(true);

            //bool isEnable = tcpClient.IsEnable;

            //isEnable = !isEnable;
            //tcpClient.IsEnable = isEnable;

            //tcpClient.startClient();

            //CommandData cdata = new CommandData();
            //cdata.EEGPara = new EEGPara();
            //cdata.EEGPara.ChannelNum = 10;
            //cdata.EEGPara.Gain = 20;
            //cdata.EEGPara.Points = 30;
            //cdata.EEGPara.SampleRate = 40;
            //cdata.EEGPara.WorkMode = 50;

            //CommandData cd2 = cdata;

            //Console.WriteLine("cd2.EEGPara" + cd2.EEGPara);
            //Console.WriteLine("cd2.MEMSPara" + cd2.MEMSPara);
            //MdcpBroadcastCommand bc = new MdcpBroadcastCommand();
            //bc.Header = new FrameHeader();
            //bc.BroadcastData = new BroadcastCommandData();
            //bc.Tail = new FrameTail();
            //byte[] message = MdcpSerializer.OrganizeBroadcastCommandWithData(bc);

            //string str = BitConverter.ToString(message);
            //byte[] decBytes = new byte[str.Length];
            ////decBytes = Convert.ToByte(str);

            //for (int i = 0; i < str.Length; i++)
            //{
            //    decBytes[i] = Convert.ToByte(str[i]);
            //}

            //UDPController.SendBroadcastMsg(message, 8999);

            //BB localBB = new BB();
            //localBB.innerA = new AA();

            //localBB.email = "chaingun76@163.com";
            //localBB.innerA.address = "Beijing";
            //localBB.innerA.age = 45;
            //localBB.innerA.name = "chaingun";
            //localBB.salary = 5000;
            //dumpBB(localBB);

            //BB b1 = copy1(localBB);
            //BB b2 = copy2(localBB);
            //BB b3 = copy3(localBB);

            //localBB.email = "yuki@163.com";
            //localBB.salary = 10000;
            //localBB.innerA.age = 32;
            //dumpBB(b1);
            //dumpBB(b2);
            //dumpBB(b3);
            #endregion

            Human h = new Human("Yuki", 33);
            Car c = new Car("Volve", 40);

            Child1 ch1 = new Child1();
            Child2 ch2 = new Child2();

            ch1.Dump(h);
            ch2.Dump(c);

            Console.WriteLine("Press any key to exit !");
            Console.ReadKey();
        }

        public static void dumpBB(BB localBB)
        {
            var s = string.Format("{0,-12}{1,-6}{2,-10}{3,15}{4,15}",
                                    localBB.innerA.name,
                                    localBB.innerA.age,
                                    localBB.innerA.address,
                                    localBB.email,
                                    localBB.salary);
            Console.WriteLine(s);
        }
        public static BB copy1(BB src)
        {
            BB localBB1 = src;

            return localBB1;
        }

        public static BB copy2(BB src)
        {
            BB localBB2 = new BB();
            localBB2.email = src.email;
            //localBB2.salary = src.salary;
            localBB2.innerA = src.innerA;

            return localBB2;
        }

        public static BB copy3(BB src)
        {
            BB localBB3 = new BB();
            localBB3.innerA = new AA();

            localBB3.email = src.email;
            localBB3.salary = 20000;
            //localBB3.innerA.age = src.innerA.age;
            localBB3.innerA.name = src.innerA.name;
            localBB3.innerA.address = src.innerA.address;
            return localBB3;
        }

    }

    public class AA
    {
        public int age;
        public String name;
        public String address;
    }

    public class BB
    {
        public AA innerA;
        public String email;
        public int salary;
    }

    public class MdcpSerializer
    {
        public static byte[] Serialize(object data, int size = -1)
        {
            if (size == -1)
            {
                size = Marshal.SizeOf(data);
            }
            var output = new byte[size];

            var outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);
            Marshal.StructureToPtr(data, outputHandle.AddrOfPinnedObject(), false);
            outputHandle.Free();

            return output;
        }

        public static T Deserialize<T>(byte[] bytes)
        {
            var bytesHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            var output = Marshal.PtrToStructure(bytesHandle.AddrOfPinnedObject(), typeof(T));

            bytesHandle.Free();

            return (T)output;
        }

        public static T Deserialize<T>(byte[] bytes, int startIndex)
        {
            var bytesHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            var output = Marshal.PtrToStructure(bytesHandle.AddrOfPinnedObject() + startIndex, typeof(T));

            bytesHandle.Free();

            return (T)output;
        }

        public static byte[] OrganizeBroadcastCommandWithData(MdcpBroadcastCommand broadcastcommand)
        {
            int sizeofBroadcastCommandData = Marshal.SizeOf(typeof(BroadcastCommandData)); //4
            var databytes = MdcpSerializer.Serialize(broadcastcommand.BroadcastData, sizeofBroadcastCommandData);

            int sizeofFrameHeader = Marshal.SizeOf(typeof(FrameHeader));
            int sizeofFrameTail = Marshal.SizeOf(typeof(FrameTail));

            var length = databytes.Length;
            var package = new byte[sizeofFrameHeader + length + sizeofFrameTail];

            broadcastcommand.Header.Token = 0x0FF0;
            broadcastcommand.Header.PayloadLength = (ushort)length;
            broadcastcommand.Header.PackageType = (byte)0x05;
            broadcastcommand.Header.ModuleType = (UInt16)0x02;

            broadcastcommand.Header.SubPackageType = (UInt16)0x02;
            broadcastcommand.Header.PackageSeq = 1;

            var headerbytes = MdcpSerializer.Serialize(broadcastcommand.Header);

            //从偏移量0处开始，把FrameHeader拷贝到package中，长度为 sizeofFrameHeader
            headerbytes.CopyTo(package, 0);
            if (length != 0)
            {
                //从偏移量sizeofFrameHeader处，把实际数据体拷贝到package中，长度为length
                databytes.CopyTo(package, sizeofFrameHeader);
            }

            broadcastcommand.Tail.CRC = CRCUtility.CreateCRCviaTable(package, true);
            broadcastcommand.Tail.TailToken = 0xF00F;

            var tailbytes = MdcpSerializer.Serialize(broadcastcommand.Tail);
            //从偏移量sizeofFrameHeader+length处，把FrameTail拷贝到package中，长度为 sizeofFrameTail
            tailbytes.CopyTo(package, sizeofFrameHeader + broadcastcommand.Header.PayloadLength);

            return package;
        }
    }

    public class CRCUtility
    {
        private const ushort Ini_Remainder = 0xFFFF;            // 余数初始值     CCITT:0xFFFF  CRC16:0x0000
        private const ushort Poly_Nomial = 0x1021;              // 多项式简式书写 CCITT:0x1021  CRC16:0x8005

        private const ushort BitWidth = 8 * sizeof(ushort);     //多项式位宽
        private const int TopBit = 1 << (BitWidth - 1);         //多项式最高位

        private const ushort FINAL_XOR_VALUE = 0x0000;          //结果异或值

        private static ushort[] CrcTable = new ushort[256];
        private static bool IsCrcTableAvailable = false;

        /// <summary>
        /// 逐位计算CRC校验码
        /// </summary>
        /// <param name="buf">数据</param>
        /// <returns>CRC码</returns>
        public static ushort CreateCRCviaBit(Byte[] buf)
        {
            ushort shift;
            int i, j;
            shift = Ini_Remainder;                              //寄存器初值


            for (i = 0; i < buf.Length; i++)
            {
                var temp = buf[i] << 8;
                shift ^= (ushort)temp;                          //将数据的字符与CRC寄存器进行异或，并把结果存入CRC寄存器
                for (j = 0; j < 8; j++)
                {
                    if ((shift & TopBit) != 0)                  //寄存器最高位为1
                    {
                        shift = (ushort)((shift << 1) ^ Poly_Nomial);
                    }
                    else
                    {
                        shift <<= 1;
                    }
                }
            }
            return shift;
        }

        /// <summary>
        /// 根据多项式，初始化CRC列表
        /// </summary>
        public static void IniCRCTable()
        {
            IsCrcTableAvailable = true;
            ushort remainder;                                   //余数---寄存器
            ushort dividend;                                    //被除数 
            int bit;
            for (dividend = 0; dividend < 256; dividend++)
            {
                remainder = (ushort)(dividend << (BitWidth - 8));
                for (bit = 0; bit < 8; bit++)
                {
                    if ((remainder & TopBit) != 0)
                    {
                        remainder = (ushort)((remainder << 1) ^ Poly_Nomial);
                    }
                    else
                    {
                        remainder = (ushort)(remainder << 1);
                    }
                }
                CrcTable[dividend] = remainder;
            }
        }

        /// <summary>
        /// 按字节查表的快速CRC算法。计算本字节后的CRC码，等于上一字节余式CRC码的低8位左移8位，加上上一字节CRC右移 8位和本字节之和后所求得的CRC码
        /// </summary>
        /// <param name="data">计算数据</param>
        /// <param name="isPackage">是否为数据包</param>
        /// <returns>CRC校验码</returns>
        public static ushort CreateCRCviaTable(byte[] data, bool isPackage = false)
        {
            if (!IsCrcTableAvailable)
            {
                IniCRCTable();
            }
            int offset;
            ushort tempdata = 0;
            ushort remainder = Ini_Remainder;
            var dataLength = data.Length;
            if (isPackage)
            {
                for (offset = 2; offset < dataLength - 4; offset++)
                {
                    tempdata = (ushort)((remainder >> (BitWidth - 8)) ^ data[offset]);
                    remainder = (ushort)(CrcTable[tempdata] ^ (remainder << 8));
                }
            }
            else
            {
                for (offset = 0; offset < dataLength; offset++)
                {
                    tempdata = (ushort)((remainder >> (BitWidth - 8)) ^ data[offset]);
                    remainder = (ushort)(CrcTable[tempdata] ^ (remainder << 8));
                }
            }
            return (ushort)(remainder ^ FINAL_XOR_VALUE);       //确保最后位数为16位
        }

        /// <summary>
        /// 校验下位机上传的CRC码
        /// </summary>
        /// <param name="packet">上传数据</param>
        /// <returns>校验是否正确</returns>
        public static bool MatchCRCviaTable(byte[] packet)
        {
            if (!IsCrcTableAvailable)
            {
                IniCRCTable();
            }
            int length = packet.Length;
            ushort emittedCRC = (ushort)((packet[length - 3] << 8) + packet[length - 4]);
            ushort calCRC = CreateCRCviaTable(packet, true);
            if (calCRC == emittedCRC)
            {
                return true;
            }
            return false;
        }

        public static void CorrectCRCviaTable(ref byte[] data)
        {
            //int length = data.Length;
            //byte[] calCRC = CreateCRCviaTable(data, true).ToBytes();
            //data[length - 4] = calCRC[0];
            //data[length - 3] = calCRC[1];
        }
    }
}
