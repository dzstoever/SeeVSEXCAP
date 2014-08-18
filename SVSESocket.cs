using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using log4net;

namespace SVSEXCAP
{
    public class SVSESocket
    {
        private readonly ILog log = LogManager.GetLogger("SVSESocket");

        public SVSESocket(int bufferSize)
        {
            //SVSEUtility.LogAllLevelMessages(log);

            _bufferSize = bufferSize;
            
            OnConnected += _OnConnected;
            OnDisconnected += _OnDisconnected;
            OnDataSent += _OnDataSent;
            OnDataIn += _OnDataIn;
            OnError += _OnError;            
        }

        ~SVSESocket()
        {
            if (_socket != null)
            {
                if (_socket.Connected)
                    _socket.Close();
                else                
                    _socket.Dispose();
            }
        }


        #region public events

        public event Action<object, bool> OnConnected;
        public event Action<object, bool> OnDisconnected;
        public event Action<object, string> OnDataSent;
        public event Action<object, byte[]> OnDataIn;
        public event Action<object, Exception> OnError;

        
        void _OnConnected(object sender, bool connected)
        {
            if (connected)
                log.DebugFormat("Connected to [{0}:{1}]", RemoteIPAddress, RemoteIPEndpoint.Port);
        }

        void _OnDisconnected(object sender, bool connected)
        {
            if (!connected)
                log.DebugFormat("Disconnected from [{0}:{1}]", RemoteIPAddress, RemoteIPEndpoint.Port);
        }

        void _OnDataSent(object sender, string data)
        {
            log.DebugFormat("{0} sent to {1}:{2}", data.Replace("\n", ""), RemoteIPAddress, RemoteIPEndpoint.Port);
        }

        void _OnDataIn(object sender, byte[] data)
        {
            log.DebugFormat("{0} bytes received from {1}:{2}", data.Length, RemoteIPAddress, RemoteIPEndpoint.Port);
        }

        void _OnError(object sender, Exception exc)
        {
            log.Error("Communication error occured!");
        }

        #endregion
        

        public bool Connected
        {
            get
            {
                if (_socket == null) return false;
                return _socket.Connected;
            }
        }
        public string EOL { get; set; }
        public IPAddress RemoteIPAddress { get; private set; }
        public IPEndPoint RemoteIPEndpoint { get; private set; }
        
                
        public void Connect(EndPoint remoteEP)
        {
            RemoteIPEndpoint = (IPEndPoint)remoteEP;
            RemoteIPAddress = RemoteIPEndpoint.Address;

            if (_socket != null) _socket.Close();
            _socket = SVSEUtility.CreateSocket();

            // Create the state object.
            StateObject state = new StateObject(_bufferSize);
            state.WorkSocket = _socket; 
            
            // Connect to the remote endpoint.
            _socket.BeginConnect(remoteEP,
                new AsyncCallback(ConnectCallback), state);
            _connectDone.WaitOne();
        }
        private void ConnectCallback(IAsyncResult ar)
        {
            // Retrieve the state object and socket from the state object.
            StateObject state = (StateObject)ar.AsyncState;
            try
            {
                // Complete the connection.
                state.WorkSocket.EndConnect(ar);

                // Wait for data to arrive.
                Receive(_bufferSize);
            }
            catch (Exception exc)
            {
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, exc);
            }

            // Signal that the connection attempt is complete.
            _connectDone.Set();

            // Bubble the event
            if (OnConnected.GetInvocationList().Length > 0)
                OnConnected(this, _socket.Connected);
        }
        
        public void Send(String data, int bufferSize)
        {
            // Create the state object.
            StateObject state = new StateObject(_bufferSize);
            state.WorkSocket = _socket;
            state.TextSent = data;

            // Convert the string data to byte data using ASCII encoding.
            byte[] byteData = Encoding.ASCII.GetBytes(data);

            // Begin sending the data to the remote device.
            _socket.BeginSend(byteData, 0, byteData.Length, SocketFlags.None,
                new AsyncCallback(SendCallback), state);
        }
        private void SendCallback(IAsyncResult ar)
        {
            // Retrieve the state object and the client socket from the asynchronous state object.
            StateObject state = (StateObject)ar.AsyncState;
            try
            {
                // Complete sending the data to the remote device.
                int bytesSent = state.WorkSocket.EndSend(ar);

                // Signal that all bytes have been sent.
                _sendDone.Set();

                // Bubble the event
                if (OnDataSent.GetInvocationList().Length > 0)
                    OnDataSent(this, state.TextSent);
            }
            catch (Exception exc)
            {
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, exc);
            }
            
        }
        
        public void Receive(int bufferSize)
        {
            // Create the state object.
            StateObject state = new StateObject(_bufferSize);
            state.WorkSocket = _socket;

            // Begin receiving the data from the remote device.
            _socket.BeginReceive(state.DataRcvd, 0, _bufferSize, SocketFlags.None,
                new AsyncCallback(ReceiveCallback), state);
        }
        private void ReceiveCallback(IAsyncResult ar)
        {
            // Retrieve the state object and the client socket from the asynchronous state object.
            StateObject state = (StateObject)ar.AsyncState;
            try
            {
                // Read data from the remote device.
                int bytesRead = state.WorkSocket.EndReceive(ar);
                if (bytesRead == 0)
                {
                    // Socket Shutdown is complete, so lets disconnect
                    _socket.BeginDisconnect(true,
                        new AsyncCallback(DisconnectCallback), _socket);
                    _disconnectDone.WaitOne();
                    return;
                }

                if (EOL != null)
                {
                    string rcvd = Encoding.ASCII.GetString(state.DataRcvd, 0, bytesRead);
                    if (state.TextRcvd == null)
                        state.TextRcvd = new StringBuilder();//...this must be the first receive
                    state.TextRcvd.Append(rcvd);

                    if (rcvd.EndsWith(EOL))
                    {
                        // Signal that all bytes have been received.
                        _receiveDone.Set();
                    }
                    
                    // Bubble the event
                    if( OnDataIn.GetInvocationList().Length > 0)
                        OnDataIn(this, state.DataRcvd);
                }
                else
                {
                    // Get the actual data received, and put it into a dynamically sized buffer
                    byte[] buffer = new byte[bytesRead];
                    Buffer.BlockCopy(state.DataRcvd, 0, buffer, 0, bytesRead);                    

                    // Clear the buffer
                    state.DataRcvd = new byte[state.BufferSize];

                    // Bubble the event
                    OnDataIn(this, buffer);
                }

                // Wait for more data
                Receive(_bufferSize);
            }
            catch (Exception exc)
            {
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, exc);
            }
        }

        public void Disconnect()
        {
            // Wait for shutdown processing to complete (e.g. ReceiveAsync() will return 0 bytes).
            // .Disconnect will be called from ReceiveCallback...
            _socket.Shutdown(SocketShutdown.Both);
        }
        private void DisconnectCallback(IAsyncResult ar)
        {
            // Retrieve the socket from the state object.
            Socket socket = (Socket)ar.AsyncState;
            try
            {
                // Complete the disconnect.
                socket.EndDisconnect(ar);
            }
            catch (Exception exc)
            {
                if (OnError.GetInvocationList().Length > 0)
                    OnError(this, exc);
            }

            // Signal that the disconnect is complete.
            _disconnectDone.Set();

            // Bubble the event
            if (OnDisconnected.GetInvocationList().Length > 0)
                OnDisconnected(this, _socket.Connected);            
        }


        #region private members

        /// <summary>
        /// We maintain a member socket here which is recreated every time we connect.
        /// Note: We also maintain a 'WorkSocket' as a member of the StateObject.
        /// </summary>
        private Socket _socket;
        private int _bufferSize;

        private ManualResetEvent _connectDone = new ManualResetEvent(false);
        private ManualResetEvent _sendDone = new ManualResetEvent(false);
        private ManualResetEvent _receiveDone = new ManualResetEvent(false);
        private ManualResetEvent _disconnectDone = new ManualResetEvent(false);

        #endregion
        

        #region nested asynchronous state object

        class StateObject
        {
            public StateObject(int bufferSize)
            {
                BufferSize = bufferSize;
                DataRcvd = new byte[bufferSize];
            }

            /// <summary>
            /// Raw socket
            /// </summary> 
            internal Socket WorkSocket = null;
            /// <summary>
            /// Size of receive buffer.
            /// </summary> 
            internal int BufferSize { get; private set; }
            /// <summary>
            /// Receive data buffer.        
            /// </summary>
            internal byte[] DataRcvd { get; set; }
            /// <summary>
            /// Received data string.
            /// </summary> 
            internal StringBuilder TextRcvd;
            /// <summary>
            /// Sent data string
            /// </summary> 
            internal string TextSent;

            // Note: we are not accumulating data here, instead we will let tje SVSEClient handle that 
            // Received raw data
            // internal System.Collections.Queue DataQueue = new System.Collections.Queue();

            //public int DataLength 
            //{
            //    get 
            //    {
            //        int len =0;
            //        var x = DataQueue.ToArray().GetEnumerator();
            //        while (x.MoveNext())
            //        {

            //            byte[]  b =  (byte[])x.Current;
            //            len += b.Length;
            //            x.MoveNext();
            //        }
            //        return len;
            //    }
            //}

        }

        #endregion

    }
}
