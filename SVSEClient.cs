using System;
using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using log4net;

namespace SVSEXCAP
{
    public class SVSEClient
    {
        private readonly ILog log = LogManager.GetLogger("SVSEClient");        

        public SVSEClient()
        {
            //SVSEUtility.LogAllLevelMessages(log);

            _socketComm = new SVSESocket(17);// 16 + linefeed
            _socketComm.EOL = "\n";		     // command responses must end with a linefeed
            _socketComm.OnConnected += socketComm_OnConnected;
            _socketComm.OnDisconnected += socketComm_OnDisconnected;
            _socketComm.OnDataSent += socketComm_OnDataSent;
            _socketComm.OnDataIn += socketComm_OnDataIn;            
            _socketComm.OnError += socketComm_OnError;

            _socketData = new SVSESocket(65536);
            _socketData.OnConnected += socketData_OnConnected;
            _socketData.OnDisconnected += socketData_OnDisconnected;
            //_socketData.OnDataSent += socketData_OnDataSent; we don't send data on this port
            _socketData.OnDataIn += socketData_OnDataIn;
            _socketData.OnError += socketData_OnError;

            OnConnected += SVSEClient_OnConnected;
            OnDisconnected += SVSEClient_OnDisconnected;
            OnTraceDataIn += SVSEClient_OnTraceDataIn;
            OnError += SVSEClient_OnError;

        }


        #region public events

        public event Action<object, bool> OnConnected;
        public event Action<object, bool> OnDisconnected;
        public event Action<object, byte[]> OnTraceDataIn;
        public event Action<object, Exception> OnError;

        //
        // Note: the following handlers assure that we don't get exceptions with no subscribers
        //
        void SVSEClient_OnConnected(object sender, bool connected)
        {
            if(connected)
                log.InfoFormat("Connected to [{0}]", _ipAddress.ToString());
        }

        void SVSEClient_OnDisconnected(object sender, bool connected)
        {
            if (!connected)
                log.InfoFormat("Disconnected from [{0}]", _ipAddress.ToString());
        }

        void SVSEClient_OnTraceDataIn(object sender, byte[] data)
        {
            log.Info("Trace Data Received.");            
        }

        void SVSEClient_OnError(object sender, Exception exc)
        {
            log.Fatal("", exc);           
        }

        #endregion


        /// <summary>
        /// This is set every time .Startup is called
        /// </summary>
        public IPAddress IpAddress
        {
            get { return _ipAddress; }
        }

        /// <summary>
        /// Indicates whether the command port is connected
        /// </summary>
        public bool Connected
        {
            get { return _socketComm.Connected; }
        }

        /// <summary>
        /// This value is set in response to the HARTBEAT command
        /// Note: the SVSECapture needs this to create the .pcap file
        /// </summary>
        public int UtcOffset
        {
            get { return _utcOffset; }
        }


        public void Startup(string host, int port, string userId, string password)
        {
            _userId = userId.Trim();
            _password = password.Trim();

            try
            {
                var endpoint = SVSEUtility.CreateIPEndpoint(host.Trim(), port, out _ipAddress);
                _socketComm.Connect(endpoint);
            }
            catch (Exception exc)
            {
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, exc);
            }
        }

        public void GetTraceData()
        {
            _POLLDATA.BytesExpected = -1;
            _POLLDATA.ClearQs();
            SendPollCommand(SVSECommands.TRACIP01);
        }

        public void Disconnect()
        {
            if (_socketData != null && _socketData.Connected)
                _socketData.Disconnect();

            if (_socketComm != null && _socketComm.Connected)
                _socketComm.Disconnect();
        }


        #region socket event handlers + command callbacks
        //
        // This is where we are coordinating all communication with the server
        //

        void socketComm_OnConnected(object sender, bool connected)
        {
            if (connected)
            {
                Thread.Sleep(1000);
                SendPollCommand(SVSECommands.LOGIN);
            }

            //throw event
            if( OnConnected.GetInvocationList().Length > 0)
                OnConnected(this, connected);
        }

        void socketComm_OnDisconnected(object sender, bool connected)
        {
            if (connected && OnError.GetInvocationList().Length > 0)
                OnError(this, new Exception("Failed to disconnect on command port."));

            //throw event
            if (OnDisconnected.GetInvocationList().Length > 0)
                OnDisconnected(sender, connected);
        }

        void socketComm_OnDataSent(object sender, string data)
        {
            int length = data.IndexOf(' ') < 0 ? 8 : data.IndexOf(' ');            
            log.InfoFormat("Sent: {0}", data.Substring(0, length));
        }

        void socketComm_OnDataIn(object sender, byte[] data)
        {
            string text = Encoding.ASCII.GetString(data);
            _RESPONSE.Text = text.Substring(0, 16);//remove the CRLF
            log.InfoFormat("Rcvd: {0}", _RESPONSE.Text);

            if (_RESPONSE.Handle != null)//LOGIN, OPENDATA, HARTBEAT
            {
                _eventRESPONSE.Set();//Execute the waiting method
            }
            else if (text.StartsWith("FAIL"))//Capture Failed
            {
                if (_POLLDATA.HandleWAIT != null) { _POLLDATA.HandleWAIT.Unregister(null); _POLLDATA.HandleWAIT = null; }// Stop future execution of the callback method
                if (_POLLDATA.HandleDONE != null) { _POLLDATA.HandleDONE.Unregister(null); _POLLDATA.HandleDONE = null; }// Stop future execution of the callback method 

                _POLLDATA.ClearQs();
                string description = "Capture failed! ";
                switch (text)
                {
                    case "FAILTRACTDNZFAIL": description += "The buffer is not full.";
                        break;
                    default: description += text;
                        break;
                }
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, new Exception(description));
            }
            else
            {   //Capture Succeeded
                if (text.Substring(8, 4) == "DONE")
                {
                    // The server has finished sending data but it is possible that we 
                    // have not received it all on the data port, so this will cause the 
                    // callback method to run periodically until all the data is received
                    _POLLDATA.HandleWAIT = ThreadPool.RegisterWaitForSingleObject(
                                _eventCHECKDATA,                             //Register Wait Handle
                                new WaitOrTimerCallback(CallbackCHECKDATA),  //Delegate/method to call when signaled
                                null,                                        //Object passed to the delegate
                                msRecheckData,                               //Timeout
                                false);

                    _eventCHECKDATA.Set();//Check now
                }
                else
                {   //Store the response
                    SVSEResponse response = new SVSEResponse();
                    response.Text = _currCommand.ToString();
                    response.Count = Convert.ToInt32(text.Substring(4, 4), 10);
                    response.Length = Convert.ToInt32(text.Substring(8, 4), 10);
                    _POLLDATA.GoodQ.Enqueue(response);
                }
            }
        }

        void socketComm_OnError(object sender, Exception exc)
        {
            // throw event
            if (OnError.GetInvocationList().Length > 0)
                OnError(sender, exc);
        }


        void socketData_OnConnected(object sender, bool connected)
        {
            if (connected)
            {
                Thread.Sleep(1000);
                SendPollCommand(SVSECommands.HARTBEAT);
            }
        }

        void socketData_OnDisconnected(object sender, bool connected)
        {
            if (connected  && OnError.GetInvocationList().Length > 0)
                OnError(this, new Exception("Failed to disconnect on command port."));
        }

        void socketData_OnDataIn(object sender, byte[] data)
        {
            if (_currCommand == SVSECommands.TRACIP01 && _POLLDATA.BytesExpected == -1)
                _POLLDATA.BytesExpected = StoreTraceLength(data);
            else
                _POLLDATA.DataQ.Enqueue(data);
        }

        void socketData_OnError(object sender, Exception exc)
        {
            // Bubble the event
            if (OnError.GetInvocationList().Length > 0)
                OnError(sender, exc);
        }


        private void CallbackLOGIN(object state, bool timedOut)
        {
            if (_RESPONSE.Handle != null) { _RESPONSE.Handle.Unregister(null); _RESPONSE.Handle = null; }// Stop future execution of the callback method
            if (timedOut  && OnError.GetInvocationList().Length > 0) { OnError(this, new Exception("LOGIN: Timed Out.")); }
            else
            {
                if (_RESPONSE.Text.StartsWith("GOOD") && _RESPONSE.Text.EndsWith("GOOD"))
                {
                    //open the data port
                    SendPollCommand(SVSECommands.OPENDATA);
                }
                else
                {
                    string loginMess = "Login failed! ";
                    switch (_RESPONSE.Text.Substring(4, 8))
                    {
                        case "LGINSAIN":
                            loginMess += "User already logged in.";
                            break;
                        case "LGINALGI":
                            loginMess += "User already logged in.";
                            break;
                        default:
                            loginMess += _RESPONSE.Text.Substring(4, 8);
                            break;
                    }
                    if (OnError.GetInvocationList().Length > 0)
                        OnError(this, new Exception(loginMess));
                }
            }
        }

        private void CallbackOPENDATA(object state, bool timedOut)
        {
            if (_RESPONSE.Handle != null) { _RESPONSE.Handle.Unregister(null); _RESPONSE.Handle = null; }// Stop future execution of the callback method
            if (timedOut && OnError.GetInvocationList().Length > 0) { OnError(this, new Exception("OPENDATA: Timed Out.")); }
            else
            {
                if (_RESPONSE.Text.StartsWith("GOOD") && _RESPONSE.Text.EndsWith("GOOD"))
                {
                    // Try to connect to the data port
                    int dataport = Convert.ToInt32(_RESPONSE.Text.Substring(4, 8), 16);
                    var endpoint = SVSEUtility.CreateIPEndpoint(_socketComm.RemoteIPAddress.ToString(), dataport);
                    _socketData.Connect(endpoint);
                }
                else if (_RESPONSE.Text.StartsWith("FAIL"))
                {
                    if (OnError.GetInvocationList().Length > 0)
                        OnError(this, new Exception("OPENDATA: " + _RESPONSE.Text));
                }
            }
        }

        private void CallbackHARTBEAT(object state, bool timedOut)
        {
            if (_RESPONSE.Handle != null) { _RESPONSE.Handle.Unregister(null); _RESPONSE.Handle = null; }// Stop future execution of the callback method
            if (timedOut && OnError.GetInvocationList().Length > 0) { OnError(this, new Exception("HARTBEAT: Timed Out.")); }
            else
            {
                if (_RESPONSE.Text.StartsWith("GOOD") && _RESPONSE.Text.EndsWith("GOOD"))
                {
                    _utcOffset = Convert.ToInt32(_RESPONSE.Text.Substring(4, 8), 16);
                    log.Info("Ready to capture data.");
                }
                else if (_RESPONSE.Text.StartsWith("FAIL"))
                {
                    if (OnError.GetInvocationList().Length > 0)
                        OnError(this, new Exception("HARTBEAT: " + _RESPONSE.Text));
                }
            }
        }

        private void CallbackCHECKDATA(object state, bool timedOut)
        {
            log.DebugFormat("CHECKDATA [Expected={0}, Received={1}]", _POLLDATA.BytesExpected, _POLLDATA.BytesReceived);
            if (_POLLDATA.BytesExpected > 0 && _POLLDATA.BytesExpected == _POLLDATA.BytesReceived)
            {
                _eventTRACEDONE.Set();
            }
            else if (_POLLDATA.BytesExpected < _POLLDATA.BytesReceived)
            {
                if (_POLLDATA.HandleWAIT != null) { _POLLDATA.HandleWAIT.Unregister(null); _POLLDATA.HandleWAIT = null; }// Stop future execution of the callback method
                if (_POLLDATA.HandleDONE != null) { _POLLDATA.HandleDONE.Unregister(null); _POLLDATA.HandleDONE = null; }// Stop future execution of the callback method
                _POLLDATA.ClearQs();

                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, new Exception(string.Format(
                        "Data Overflow [Expected={0}, Received={1}]", _POLLDATA.BytesExpected, _POLLDATA.BytesReceived)));
            }
            //check for more data every... msRecheckData
        }

        private void CallbackTRACEDONE(object state, bool timedOut)
        {
            if (_POLLDATA.HandleWAIT != null) { _POLLDATA.HandleWAIT.Unregister(null); _POLLDATA.HandleWAIT = null; }// Stop future execution of the callback method
            if (_POLLDATA.HandleDONE != null) { _POLLDATA.HandleDONE.Unregister(null); _POLLDATA.HandleDONE = null; }// Stop future execution of the callback method        

            if (timedOut && OnError.GetInvocationList().Length > 0) { OnError(this, new Exception("Capture Failed! Timed Out.")); }
            else
            {
                byte[] data = _POLLDATA.GetDataQ();

                // throw event
                if( OnTraceDataIn.GetInvocationList().Length > 0)
                    OnTraceDataIn(this, data);
            }
        }

        #endregion
        

        #region private members

        private const int msResponseTimeout = 60000;//1 min                
        private const int msTraceTimeout = 300000;  //5 min
        private const int msRecheckData = 3000;     //3 sec

        private int _utcOffset;
        private string _userId;
        private string _password;
        private IPAddress _ipAddress;
        private SVSESocket _socketComm;
        private SVSESocket _socketData;
        private SVSECommands _currCommand;
        private SVSECommState _RESPONSE = new SVSECommState();
        private SVSEDataState _POLLDATA = new SVSEDataState();

        private AutoResetEvent _eventRESPONSE = new AutoResetEvent(false);
        private AutoResetEvent _eventCHECKDATA = new AutoResetEvent(false);
        private AutoResetEvent _eventTRACEDONE = new AutoResetEvent(false);

        #endregion


        #region private methods

        /// <summary>
        /// Build a TCP/IP command to send to the server.
        /// </summary>        
        private byte[] BuildTcpIpCommand(string text)
        {
            byte[] command = new ASCIIEncoding().GetBytes(text + "\n");

            byte[] flags = new byte[4] { 0x54, 0x20, 0x20, 0x20 };
            int length = flags.Length + command.Length;// + _consoleToken.Length
            byte[] lengthBE = System.BitConverter.GetBytes(SVSEUtility.SwapEndian((uint)length));
            byte[] data = new byte[length + lengthBE.Length];
            int offset = 0;

            lengthBE.CopyTo(data, offset); offset += lengthBE.Length;
            flags.CopyTo(data, offset); offset += flags.Length;
            command.CopyTo(data, offset);

            return data;
        }

        /// <summary>
        /// Send the next poll command and register wait handles
        /// </summary>
        /// <param name="COMMAND"></param>
        private void SendPollCommand(SVSECommands COMMAND)
        {
            _currCommand = COMMAND;
            string CmdTxt = "";
            switch (COMMAND)
            {
                case SVSECommands.LOGIN:
                    CmdTxt = String.Format("LOGIN {0} {1}", _userId, _password) + "\n";
                    _RESPONSE.Handle = ThreadPool.RegisterWaitForSingleObject(
                        _eventRESPONSE,                               //Register Wait Handle
                        new WaitOrTimerCallback(CallbackLOGIN),     //Delegate/method to call when signaled
                        COMMAND,                                    //Object passed to the delegate
                        msResponseTimeout,                          //Timeout
                        true);
                    break;
                case SVSECommands.OPENDATA:
                    string verStr = "010500";
                    CmdTxt = "OPENDATA " + verStr + "\n";
                    _RESPONSE.Handle = ThreadPool.RegisterWaitForSingleObject(
                        _eventRESPONSE,                               //Register Wait Handle
                        new WaitOrTimerCallback(CallbackOPENDATA),  //Delegate/method to call when signaled
                        COMMAND,                                    //Object passed to the delegate
                        msResponseTimeout,                          //Timeout
                        true);
                    break;
                case SVSECommands.HARTBEAT:
                    CmdTxt = COMMAND.ToString() + "\n";
                    _RESPONSE.Handle = ThreadPool.RegisterWaitForSingleObject(
                        _eventRESPONSE,                               //Register Wait Handle
                        new WaitOrTimerCallback(CallbackHARTBEAT),  //Delegate/method to call when signaled
                        COMMAND,                                    //Object passed to the delegate
                        msResponseTimeout,                          //Timeout
                        true);
                    break;
                case SVSECommands.TRACIP01:
                    CmdTxt = "GETDATA " + COMMAND.ToString() + "\n";
                    _POLLDATA.HandleDONE = ThreadPool.RegisterWaitForSingleObject(
                        _eventTRACEDONE,                           //Register Wait Handle
                        new WaitOrTimerCallback(CallbackTRACEDONE),//Delegate/method to call when signaled
                        COMMAND,                                    //Object passed to the delegate
                        msTraceTimeout,                            //Timeout
                        true);
                    break;
                default:
                    //This should never happen...
                    CmdTxt = "GETDATA " + COMMAND.ToString() + "\n";
                    break;
            }

            if (_socketComm.Connected)
            {
                _socketComm.Send(CmdTxt, 17);
            }
            else if (OnError.GetInvocationList().Length > 0)
            {
                OnError(this, new Exception(string.Format(
                    "Couldn't send command (connection unavailable): {0}", COMMAND)));
            }
        }

        /// <summary>
        /// Checks the first four bytes for the total Trace Length 
        /// Stores the length in _POLLDATA object and Enqueues all bytes
        /// </summary>
        /// <param name="blok">the bytes that contain the Trace Length, plus possible overflow</param>
        /// <returns>-1 if less than four bytes have been received, otherwise the length of the trace data</returns>
        private long StoreTraceLength(byte[] newBlok)
        {
            byte[] blok;
            if (_POLLDATA.DataQ.Count == 1)//get the previous blok, should never be greater than 1
            {//Combine into 1 blok
                byte[] prevBlok = (byte[])_POLLDATA.DataQ.Dequeue();
                int len = prevBlok.Length + newBlok.Length;
                blok = new byte[len];
                int i = 0;
                for (i = 0; i < prevBlok.Length; i++)
                { blok[i] = prevBlok[i]; }
                for (i = prevBlok.Length; i < len; i++)
                { blok[i] = newBlok[i]; }
            }
            else { blok = newBlok; }

            long traceLen = -1;
            if (blok.Length >= 4)
            {
                traceLen = (long)SVSEUtility.GetUINT32(0, blok);
            }
            _POLLDATA.DataQ.Enqueue(blok);
            return traceLen;
        }

        #endregion


        #region nested asynchronous state objects

        public class SVSECommState
        {
            public RegisteredWaitHandle Handle;

            public string Text;
        }

        public class SVSEDataState
        {
            public RegisteredWaitHandle HandleWAIT;
            public RegisteredWaitHandle HandleDONE;

            public Queue GoodQ = new Queue();
            public Queue DataQ = new Queue();

            public long BytesExpected = -1;
            public long BytesReceived
            {
                get
                {
                    long total = 0;
                    foreach (byte[] array in DataQ)
                    {
                        long bytes = array.LongLength;
                        total += bytes;
                    }
                    return total;
                }
            }


            public void ClearQs()
            {
                GoodQ.Clear();
                DataQ.Clear();
            }

            public byte[] GetDataQ()
            {
                SVSEResponse response = (SVSEResponse)GoodQ.Dequeue();//There should be one response
                byte[] rawData = new byte[BytesExpected];
                long allPos = 0;				//Keep track of position
                while (DataQ.Count > 0)	        //Copy all data into one array
                {
                    byte[] bytes = (byte[])DataQ.Dequeue();
                    bytes.CopyTo(rawData, allPos);
                    allPos += bytes.Length;
                }

                //first 4 have the length
                byte[] data = new byte[rawData.Length - 4];
                for (int i = 0; i < data.Length; i++)
                { data[i] = rawData[i + 4]; }

                return data;
            }

        }

        #endregion


        #region nested helper objects

        public enum SVSECommands : int
        {
            LOGIN,
            OPENDATA,
            HARTBEAT,
            TRACIP01
        }

        public struct SVSEResponse
        {
            public string Text;
            public int Count;
            public int Length;
        }

        #endregion
    }
}
