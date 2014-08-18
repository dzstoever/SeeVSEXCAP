using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using log4net;


namespace SVSEXCAP
{
    public class SVSECapture
    {
        private readonly ILog log = LogManager.GetLogger("SVSECapture");

        /// <summary>
        /// Write a file in .cap format
        /// </summary>
        /// <param name="pcapIPpacks"></param>
        /// <param name="snaplen"></param>
        /// <param name="utcOffset"></param>
        /// <param name="path"></param>
        public void WriteFile(Queue pcapIPpacks, uint snaplen, int utcOffset, string path)
        {
            uint magic_number = 0xa1b2c3d4;
            ushort version_major = 2;
            ushort version_minor = 4;
            uint sigfigs = 0;
            uint network = 12;//data link type = WTAP_ENCAP_RAW_IP
            #region Create the global header
            byte[] globalHeader = new byte[24];
            Array.Copy(BitConverter.GetBytes(magic_number), 0, globalHeader, 0, 4);
            Array.Copy(BitConverter.GetBytes(version_major), 0, globalHeader, 4, 2);
            Array.Copy(BitConverter.GetBytes(version_minor), 0, globalHeader, 6, 2);
            Array.Copy(BitConverter.GetBytes(utcOffset), 0, globalHeader, 8, 4);
            Array.Copy(BitConverter.GetBytes(sigfigs), 0, globalHeader, 12, 4);
            Array.Copy(BitConverter.GetBytes(snaplen), 0, globalHeader, 16, 4);
            Array.Copy(BitConverter.GetBytes(network), 0, globalHeader, 20, 4);
            #endregion
            File.WriteAllBytes(path, globalHeader);
            FileStream fStream = File.OpenWrite(path);
            fStream.Position = 24;//Start after the global header
            foreach (PcapIpPacket pack in pcapIPpacks)
            {
                if (pack.Length >= 40)//40 is the minimum size for a ip and tcp header
                {
                    #region Write packet header
                    fStream.Write(pack.TsSec, 0, 4);
                    fStream.Write(pack.TsUsec, 0, 4);
                    fStream.Write(pack.InclLength, 0, 4);
                    fStream.Write(pack.OrigLength, 0, 4);
                    #endregion
                    fStream.Write(pack.IpPacket, 0, pack.IpPacket.Length);//Write the packet data                    
                }
            }
            fStream.Close();
            log.InfoFormat("File created: {0}", path);
        }
        
        /// <summary>
        /// Parses a raw data buffer into individual IP packets
        /// </summary>
        /// <param name="data">length in octets(bytes) of the largest packet</param>
        /// <param name="data">contains all of the IP packets, does not contain the length bytes
        /// <returns>collection of PcapIpPacket objects</returns>
        public Queue ProcessPackets(byte[] data, out uint snaplen, bool writeDebug)
        {
            snaplen = 0;//store max length
            Queue packQ = new Queue();  //This will hold the collection of PcapIpPacket to be written to the file
            int offset = 0;
            while (offset < data.Length - 1)
            {
                try
                {
                    PcapIpPacket pcapIpPacket;
                    offset = ReadNextPacket(offset, data, out pcapIpPacket, writeDebug);
                    if (pcapIpPacket.Length > 0)
                    {
                        if (pcapIpPacket.Length > snaplen) { snaplen = pcapIpPacket.Length; }//Store a new max length
                        packQ.Enqueue(pcapIpPacket);//Enqueue the packet to be written to the file                                                
                    }
                }
                catch (Exception exc)
                { log.Error("", exc); }
            }
            return packQ;
        }
        
        /// <summary>
        /// Read each packet
        /// </summary>
        /// <param name="data">All of the IP packets,
        /// this data contains a 12 byte header before each packet
        /// with a 4 byte length and a 8 byte store clock</param>
        /// <param name="offset">offset into the data of this packet</param>
        /// <returns>offset of next packet</returns>
        private int ReadNextPacket(int offset, byte[] data, out PcapIpPacket packet, bool writeDebug)
        {
            //RawDataConverter convert = new RawDataConverter();
            uint len = SVSEUtility.GetUINT32(offset, data);
            DateTime stck = SVSEUtility.GetDateTimeUTC(offset + 4, data);//8 byte STCK

            int offPack = offset + 12;
            //int verFromIpHeader = Convert.ToInt32(data[offPack]);
            ushort lenFromIpHeader = SVSEUtility.GetUINT16(offPack + 2, data);//2 bytes into the packet header
            packet = new PcapIpPacket();
            if (writeDebug)
            {
                Debug.WriteLine(//"[ " + verFromIpHeader.ToString() + " ]" 
                    "packet offset = " + offPack.ToString("X").PadRight(8, '0') +  //should be 69 for a IPv4 header
                    " : STCK(ss:us) = " + SVSEUtility.GetUINT64(offset + 4, data).ToString("X") + " = " + SVSEUtility.GetDateTimeUTC(offset + 4, data).ToString("MM-dd-yyyy HH:mm:ss:ffffff") +
                    " : Length = " + len.ToString().PadRight(5, ' ') + "...from IP header = " + lenFromIpHeader.ToString());
            }
            //if (verFromIpHeader == 69)//0x45 = IPv4 with a 40 byte IP header
            //{
            DateTime utcJan11970 = new DateTime(1970, 1, 1, 0, 0, 0).ToUniversalTime();//UTC time on Jan 1, 1970 00:00:00            
            TimeSpan tspan = stck.Subtract(utcJan11970);//The timespan between Jan 1, 1970 00:00:00 and the capture
            uint tsSeconds = 0;     //The number of seconds in the timespan
            uint tsUseconds = 0;    //The usec offset
            if (tspan.TotalSeconds > 0)
            {   /* tsSeconds must be rounded down with Math.Floor */
                tsSeconds = Convert.ToUInt32(Math.Floor(tspan.TotalSeconds));//Total seconds since Jan 1, 1970 00:00:00
                tsUseconds = Convert.ToUInt32(tspan.Milliseconds * 1000);   //Usec offset
            }
            uint inclLength = len;              //# of bytes actually saved in file
            uint origLength = lenFromIpHeader;  //# of bytes in packet when it was captured, in case snaplen trims it
            /* Get the header and data */
            byte[] ipPack = new byte[inclLength];
            for (int i = 0; i < ipPack.Length; i++)
            { ipPack[i] = data[offPack + i]; }
            packet = new PcapIpPacket(tsSeconds, tsUseconds, inclLength, origLength, ipPack);
            //}else if(writeDebug){Debug.Write("*ERROR not IPv4*");}
            return offPack + Convert.ToInt32(len);
        }


        #region nested structure

        public struct PcapIpPacket
        {
            public PcapIpPacket(uint tsSec, uint tsUsec, uint inclLen, uint origLen, byte[] ipPacket)
            {
                _tsSec = BitConverter.GetBytes(tsSec);
                _tsUsec = BitConverter.GetBytes(tsUsec);
                _inclLen = BitConverter.GetBytes(inclLen);
                _origLen = BitConverter.GetBytes(origLen);
                _ipPacket = ipPacket;
            }

            public uint Length
            {
                get
                {
                    if (_inclLen == null) { return 0; }//The packet has not been read
                    else { return BitConverter.ToUInt32(_inclLen, 0); }
                }
            }
            public byte[] TsSec { get { return _tsSec; } }
            public byte[] TsUsec { get { return _tsUsec; } }
            public byte[] InclLength { get { return _inclLen; } }
            public byte[] OrigLength { get { return _origLen; } }
            public byte[] IpPacket { get { return _ipPacket; } }

            private byte[] _tsSec, _tsUsec, _inclLen, _origLen;//Header fields
            private byte[] _ipPacket;//Packet Data
        }

        #endregion
    }

    
}
