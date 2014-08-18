using System;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;

namespace SVSEXCAP
{
    public static class SVSEUtility
    {
        /// <summary>
        /// helper extension to assure we update user controls on the main thread
        /// </summary>
        public static void InvokeEx<T>(this T @this, Action<T> action) where T : ISynchronizeInvoke
        {
            if (@this.InvokeRequired)
                @this.Invoke(action, new object[] { @this });
            else
                action(@this);
        }


        /// <summary>
        /// Create a TCP/IP socket. 
        /// </summary>
        public static Socket CreateSocket()
        {            
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.ExclusiveAddressUse = false;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            return socket;
        }

        public static IPEndPoint CreateIPEndpoint(string host, int port)
        {
            IPAddress ipAddress;
            return CreateIPEndpoint(host, port, out ipAddress);
        }

        public static IPEndPoint CreateIPEndpoint(string host, int port, out IPAddress ipAddress)
        {
            bool hasAlpha = false;
            for (var i = 0; i < host.Length; i++)
                if (Char.IsLetter(host[i]))
                    hasAlpha = true;

            if (hasAlpha)
            {
                IPHostEntry ipHostInfo = Dns.GetHostEntry(host);
                if (ipHostInfo.AddressList.Length > 0)
                    ipAddress = ipHostInfo.AddressList[0];
                else
                    throw new Exception("No such host found.");
            }
            else
                ipAddress = IPAddress.Parse(host);

            return new IPEndPoint(ipAddress, port);
        }


        /// <summary>
        /// Swap the bytes of an unsigned integer from low (high) order to high (low) order.
        /// </summary>
        /// <param name="value">Number to reorder.</param>
        /// <returns>Reordered number.</returns>
        public static uint SwapEndian(uint value)
        {
            return ((value & 0xFF000000) >> 24)
                 | (((value & 0x00FF0000) >> 16) << 8)
                 | (((value & 0x0000FF00) >> 8) << 16)
                 | ((value & 0x000000FF) << 24);
        }

        public static DateTime GetDateTimeUTC(int oset, byte[] datablock)
        {
            ulong STCK = GetUINT64(oset, datablock);
            DateTime dt1900 = new DateTime(1900, 1, 1, 0, 0, 0, 0,	//DateTime on 01/01/0001 00:00:00 ?same as STCK=0
                new System.Globalization.GregorianCalendar());	//Ticks = 

            return dt1900.AddMilliseconds(Convert.ToDouble(STCK / 4096000));

        }

        public static ulong GetUINT64(int oset, byte[] datablock)
        {
            ulong data_64 = 0;
            const int length = 8;
            int last_ind = 7;
            int high_byte = oset + length;
            byte[] rev_data = new byte[length];
            for (int cnt = oset; cnt < high_byte; cnt++)//Reverse byte order
            {
                rev_data[last_ind] = datablock[cnt];
                last_ind--;
            }
            data_64 = BitConverter.ToUInt64(rev_data, 0);//Convert the count to an integer
            return data_64;
        }

        public static uint GetUINT32(int oset, byte[] datablock)
        {
            uint data_32 = 0;
            const int length = 4;
            int last_ind = 3;
            int high_byte = oset + length;
            byte[] rev_data = new byte[length];
            for (int cnt = oset; cnt < high_byte; cnt++)//Reverse byte order
            {
                rev_data[last_ind] = datablock[cnt];
                last_ind--;
            }
            data_32 = BitConverter.ToUInt32(rev_data, 0);//Convert the count to an integer
            return data_32;
        }

        public static ushort GetUINT16(int oset, byte[] datablock)
        {
            ushort data_16 = 0;
            const int length = 2;
            int last_ind = 1;
            int high_byte = oset + length;
            byte[] rev_data = new byte[length];
            for (int cnt = oset; cnt < high_byte; cnt++)//Reverse byte order
            {
                rev_data[last_ind] = datablock[cnt];
                last_ind--;
            }
            data_16 = BitConverter.ToUInt16(rev_data, 0);
            return data_16;
        }


        /// <summary>
        /// used to test logging...
        /// </summary>        
        public static void LogAllLevelMessages(log4net.ILog log)
        {
            log.Debug("Hey, are you a programmer?");
            log.Info("Here's something interesting.");
            log.Warn("Uh-oh, that's disturbing.");
            log.Error("That was unexpected.");
            log.Fatal("The roof is on fire!"); 
        }
        
    }
}
