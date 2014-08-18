using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using log4net;

namespace SVSEXCAP
{
    public partial class MainForm : Form
    {        
        private readonly ILog log = LogManager.GetLogger("SVSEXCAP");
        private readonly SVSEClient _client;

        public MainForm()
        {
            InitializeComponent();

            log4net.Config.XmlConfigurator.Configure(new FileInfo("log4net.xml"));
            RtbAppender.SetRichTextBox(richTextBox1, "Rtb");
            //SVSEUtility.LogAllLevelMessages(log);

            var appSettings = ConfigurationManager.AppSettings;
            Host.Text = appSettings["DefaultHost"];
            Port.Text = appSettings["DefaultPort"];
            UserId.Text = appSettings["DefaultUserId"];
            Password.Text = appSettings["DefaultPassword"];
            FileLocation.Text = appSettings["DefaultFileLocation"];

            _client = new SVSEClient();
            _client.OnConnected += client_OnConnectionChange;
            _client.OnDisconnected += client_OnConnectionChange;
            _client.OnTraceDataIn += client_OnTraceDataIn;
            _client.OnError += client_OnError;

            uxCapture.Enabled = false;
        }


        void uxOpenLog_Click(object sender, EventArgs e)
        {
            OpenFile("SVSELOG.txt");
        }

        void uxOpenConfig_Click(object sender, EventArgs e)
        {
            OpenFile("SVSEXCAP.exe.config");
        }

        void uxExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        
        void uxConnect_Click(object sender, EventArgs e)
        {
            uxConnect.Enabled = false;

            Thread t = null;
            switch (uxConnect.Text)
            {
                case "Connect":
                    uxStatus.Text = "Connecting...";
                    t = new Thread(unused => 
                        _client.Startup(Host.Text, Convert.ToInt32(Port.Value), UserId.Text, Password.Text));                    
                    break;
                case "Disconnect":
                    uxStatus.Text = "Disconnecting...";
                    t = new Thread(unused => 
                        _client.Disconnect());                    
                    break;
            }
            // connect/disconnect on a background thread
            t.IsBackground = true;
            t.Start();
        }
                
        void uxCapture_Click(object sender, EventArgs e)
        {
            uxConnect.Enabled = false;
            uxCapture.Enabled = false;

            uxStatus.Text = "Capturing...";

            // capture on a background thread
            var t = new Thread(unused =>
                        _client.GetTraceData());            
            t.IsBackground = true;
            t.Start();
        }
                
        void uxChooseLocation_Click(object sender, EventArgs e)
        {
            folderBrowserDialog.SelectedPath = FileLocation.Text;
            var result = folderBrowserDialog.ShowDialog();
            if(result == DialogResult.OK)
                FileLocation.Text = folderBrowserDialog.SelectedPath;
        }

        void uxOpenFile_Click(object sender, EventArgs e)
        {
            openFileDialog.InitialDirectory = FileLocation.Text;
            
            var result = openFileDialog.ShowDialog();
            if (result == DialogResult.OK)
                OpenFile(openFileDialog.FileName);            
        }


        void client_OnConnectionChange(object sender, bool connected)
        {
            this.InvokeEx(
                f => f.uxStatus.Text = connected ? "Connected" : "Disconnected");
            this.InvokeEx(
                f => f.uxConnect.Text = connected ? "Disconnect" : "Connect");
            this.InvokeEx(
                f => f.uxConnect.Enabled = true);
            this.InvokeEx(
                f => f.uxCapture.Enabled = connected ? true : false);
        }

        void client_OnTraceDataIn(object sender, byte[] blok)
        {
            var pCursor = Cursor.Current;
            Cursor.Current = Cursors.WaitCursor;
            try
            {
                if (!Directory.Exists(FileLocation.Text))
                    Directory.CreateDirectory(FileLocation.Text);
                string fileName = string.Format("SVSEXCAP_{0}.pcap", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                string filePath = Path.Combine(FileLocation.Text, fileName);

                SVSECapture capture = new SVSECapture();
                uint snaplen;//max length of captured packets, could be used to limit packet size in .pcap file
                var q = capture.ProcessPackets(blok, out snaplen, false);
                capture.WriteFile(q, snaplen, _client.UtcOffset, filePath);

                log.InfoFormat("File saved: {0}", fileName);
                if (uxLaunchWireshark.Checked)
                {
                    Process p = new Process();
                    p.StartInfo = new ProcessStartInfo(filePath);
                    p.Start();
                }
            }
            finally
            {
                Cursor.Current = pCursor;
            }

            client_OnConnectionChange(sender, _client.Connected);
        }

        void client_OnError(object sender, Exception exc)
        {
            client_OnConnectionChange(sender, _client.Connected);
        }


        private void OpenFile(string fileName)
        {
            Process p = new Process();
            p.StartInfo = new ProcessStartInfo(fileName);
            p.Start();
        }



        #region Designer

        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.uxConnect = new System.Windows.Forms.Button();
            this.uxCapture = new System.Windows.Forms.Button();
            this.Host = new System.Windows.Forms.TextBox();
            this.UserId = new System.Windows.Forms.TextBox();
            this.Password = new System.Windows.Forms.TextBox();
            this.Port = new System.Windows.Forms.NumericUpDown();
            this.panel1 = new System.Windows.Forms.Panel();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.uxStatus = new System.Windows.Forms.ToolStripStatusLabel();
            this.uxLaunchWireshark = new System.Windows.Forms.CheckBox();
            this.uxOpenFile = new System.Windows.Forms.Button();
            this.uxChooseLocation = new System.Windows.Forms.Button();
            this.FileLocation = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.toolTip1 = new System.Windows.Forms.ToolTip(this.components);
            this.folderBrowserDialog = new System.Windows.Forms.FolderBrowserDialog();
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fILEToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.uxOpenLog = new System.Windows.Forms.ToolStripMenuItem();
            this.uxOpenConfig = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem1 = new System.Windows.Forms.ToolStripSeparator();
            this.uxExit = new System.Windows.Forms.ToolStripMenuItem();
            ((System.ComponentModel.ISupportInitialize)(this.Port)).BeginInit();
            this.panel1.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(41, 18);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(54, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "host : port";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(41, 46);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(38, 13);
            this.label2.TabIndex = 5;
            this.label2.Text = "user id";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(41, 72);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(52, 13);
            this.label3.TabIndex = 8;
            this.label3.Text = "password";
            // 
            // uxConnect
            // 
            this.uxConnect.Location = new System.Drawing.Point(364, 15);
            this.uxConnect.Name = "uxConnect";
            this.uxConnect.Size = new System.Drawing.Size(81, 23);
            this.uxConnect.TabIndex = 3;
            this.uxConnect.Text = "Connect";
            this.toolTip1.SetToolTip(this.uxConnect, "Connect to the SVSESRVR");
            this.uxConnect.UseVisualStyleBackColor = true;
            this.uxConnect.Click += new System.EventHandler(this.uxConnect_Click);
            // 
            // uxCapture
            // 
            this.uxCapture.Location = new System.Drawing.Point(457, 14);
            this.uxCapture.Name = "uxCapture";
            this.uxCapture.Size = new System.Drawing.Size(81, 23);
            this.uxCapture.TabIndex = 4;
            this.uxCapture.Text = "Capture";
            this.toolTip1.SetToolTip(this.uxCapture, "Capture trace data and create a .pcap file");
            this.uxCapture.UseVisualStyleBackColor = true;
            this.uxCapture.Click += new System.EventHandler(this.uxCapture_Click);
            // 
            // Host
            // 
            this.Host.Location = new System.Drawing.Point(107, 17);
            this.Host.Name = "Host";
            this.Host.Size = new System.Drawing.Size(160, 20);
            this.Host.TabIndex = 1;
            this.toolTip1.SetToolTip(this.Host, "IP Address or Hostname where the SVSESRVR is running");
            // 
            // UserId
            // 
            this.UserId.Location = new System.Drawing.Point(107, 43);
            this.UserId.Name = "UserId";
            this.UserId.Size = new System.Drawing.Size(160, 20);
            this.UserId.TabIndex = 6;
            // 
            // Password
            // 
            this.Password.Location = new System.Drawing.Point(107, 69);
            this.Password.Name = "Password";
            this.Password.PasswordChar = '*';
            this.Password.Size = new System.Drawing.Size(160, 20);
            this.Password.TabIndex = 9;
            // 
            // Port
            // 
            this.Port.Location = new System.Drawing.Point(274, 17);
            this.Port.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.Port.Minimum = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.Port.Name = "Port";
            this.Port.Size = new System.Drawing.Size(74, 20);
            this.Port.TabIndex = 2;
            this.toolTip1.SetToolTip(this.Port, "SVSESRVR command port (default=5450)");
            this.Port.Value = new decimal(new int[] {
            1,
            0,
            0,
            0});
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.statusStrip1);
            this.panel1.Controls.Add(this.uxLaunchWireshark);
            this.panel1.Controls.Add(this.uxOpenFile);
            this.panel1.Controls.Add(this.uxChooseLocation);
            this.panel1.Controls.Add(this.FileLocation);
            this.panel1.Controls.Add(this.label4);
            this.panel1.Controls.Add(this.label1);
            this.panel1.Controls.Add(this.Port);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.Password);
            this.panel1.Controls.Add(this.label3);
            this.panel1.Controls.Add(this.UserId);
            this.panel1.Controls.Add(this.uxConnect);
            this.panel1.Controls.Add(this.Host);
            this.panel1.Controls.Add(this.uxCapture);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(0, 24);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(584, 151);
            this.panel1.TabIndex = 0;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.uxStatus});
            this.statusStrip1.Location = new System.Drawing.Point(0, 129);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(584, 22);
            this.statusStrip1.SizingGrip = false;
            this.statusStrip1.TabIndex = 14;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // uxStatus
            // 
            this.uxStatus.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.uxStatus.ForeColor = System.Drawing.Color.DodgerBlue;
            this.uxStatus.Name = "uxStatus";
            this.uxStatus.Size = new System.Drawing.Size(569, 17);
            this.uxStatus.Spring = true;
            this.uxStatus.Text = "Disconnected";
            this.uxStatus.TextAlign = System.Drawing.ContentAlignment.BottomRight;
            // 
            // uxLaunchWireshark
            // 
            this.uxLaunchWireshark.AutoSize = true;
            this.uxLaunchWireshark.CheckAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.uxLaunchWireshark.Checked = true;
            this.uxLaunchWireshark.CheckState = System.Windows.Forms.CheckState.Checked;
            this.uxLaunchWireshark.Location = new System.Drawing.Point(360, 42);
            this.uxLaunchWireshark.Name = "uxLaunchWireshark";
            this.uxLaunchWireshark.Size = new System.Drawing.Size(178, 17);
            this.uxLaunchWireshark.TabIndex = 7;
            this.uxLaunchWireshark.Text = "Launch Wireshark Automatically";
            this.uxLaunchWireshark.UseVisualStyleBackColor = true;
            // 
            // uxOpenFile
            // 
            this.uxOpenFile.Location = new System.Drawing.Point(457, 96);
            this.uxOpenFile.Name = "uxOpenFile";
            this.uxOpenFile.Size = new System.Drawing.Size(81, 23);
            this.uxOpenFile.TabIndex = 13;
            this.uxOpenFile.Text = "Open File";
            this.toolTip1.SetToolTip(this.uxOpenFile, "Open an existing .pcap file");
            this.uxOpenFile.UseVisualStyleBackColor = true;
            this.uxOpenFile.Click += new System.EventHandler(this.uxOpenFile_Click);
            // 
            // uxChooseLocation
            // 
            this.uxChooseLocation.Location = new System.Drawing.Point(415, 97);
            this.uxChooseLocation.Name = "uxChooseLocation";
            this.uxChooseLocation.Size = new System.Drawing.Size(30, 22);
            this.uxChooseLocation.TabIndex = 12;
            this.uxChooseLocation.Text = "...";
            this.uxChooseLocation.UseVisualStyleBackColor = true;
            this.uxChooseLocation.Click += new System.EventHandler(this.uxChooseLocation_Click);
            // 
            // FileLocation
            // 
            this.FileLocation.Location = new System.Drawing.Point(107, 98);
            this.FileLocation.Name = "FileLocation";
            this.FileLocation.ReadOnly = true;
            this.FileLocation.Size = new System.Drawing.Size(309, 20);
            this.FileLocation.TabIndex = 11;
            this.FileLocation.Text = "C:\\";
            this.toolTip1.SetToolTip(this.FileLocation, "Path where .pcap files will be saved");
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(41, 102);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(60, 13);
            this.label4.TabIndex = 10;
            this.label4.Text = "file location";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.richTextBox1);
            this.groupBox1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.groupBox1.Location = new System.Drawing.Point(0, 175);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(584, 236);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Event Log";
            // 
            // richTextBox1
            // 
            this.richTextBox1.BackColor = System.Drawing.Color.Black;
            this.richTextBox1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.richTextBox1.Font = new System.Drawing.Font("Consolas", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.richTextBox1.Location = new System.Drawing.Point(3, 16);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(578, 217);
            this.richTextBox1.TabIndex = 0;
            this.richTextBox1.Text = "";
            // 
            // openFileDialog
            // 
            this.openFileDialog.DefaultExt = "pcap";
            this.openFileDialog.Filter = "Wireshark files|*.pcap|All files|*.*";
            this.openFileDialog.Title = "Open a Wireshark File";
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fILEToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(584, 24);
            this.menuStrip1.TabIndex = 2;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fILEToolStripMenuItem
            // 
            this.fILEToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.uxOpenLog,
            this.uxOpenConfig,
            this.toolStripMenuItem1,
            this.uxExit});
            this.fILEToolStripMenuItem.Name = "fILEToolStripMenuItem";
            this.fILEToolStripMenuItem.Size = new System.Drawing.Size(40, 20);
            this.fILEToolStripMenuItem.Text = "FILE";
            // 
            // uxOpenLog
            // 
            this.uxOpenLog.Name = "uxOpenLog";
            this.uxOpenLog.Size = new System.Drawing.Size(142, 22);
            this.uxOpenLog.Text = "Open &Log";
            this.uxOpenLog.Click += new System.EventHandler(this.uxOpenLog_Click);
            // 
            // uxOpenConfig
            // 
            this.uxOpenConfig.Name = "uxOpenConfig";
            this.uxOpenConfig.Size = new System.Drawing.Size(142, 22);
            this.uxOpenConfig.Text = "Open &Config";
            this.uxOpenConfig.Click += new System.EventHandler(this.uxOpenConfig_Click);
            // 
            // toolStripMenuItem1
            // 
            this.toolStripMenuItem1.Name = "toolStripMenuItem1";
            this.toolStripMenuItem1.Size = new System.Drawing.Size(139, 6);
            // 
            // uxExit
            // 
            this.uxExit.Name = "uxExit";
            this.uxExit.Size = new System.Drawing.Size(142, 22);
            this.uxExit.Text = "E&xit";
            this.uxExit.Click += new System.EventHandler(this.uxExit_Click);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(584, 411);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.panel1);
            this.Controls.Add(this.menuStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "MainForm";
            this.Text = "SVSEXCAP";
            ((System.ComponentModel.ISupportInitialize)(this.Port)).EndInit();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button uxConnect;
        private System.Windows.Forms.Button uxCapture;
        private System.Windows.Forms.TextBox Host;
        private System.Windows.Forms.TextBox UserId;
        private System.Windows.Forms.TextBox Password;
        private System.Windows.Forms.NumericUpDown Port;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RichTextBox richTextBox1;
        private System.Windows.Forms.Button uxChooseLocation;
        private System.Windows.Forms.TextBox FileLocation;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.ToolTip toolTip1;
        private System.Windows.Forms.Button uxOpenFile;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog;
        private System.Windows.Forms.CheckBox uxLaunchWireshark;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel uxStatus;
        private System.Windows.Forms.OpenFileDialog openFileDialog;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fILEToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem uxOpenLog;
        private System.Windows.Forms.ToolStripMenuItem uxOpenConfig;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem1;
        private System.Windows.Forms.ToolStripMenuItem uxExit;

        #endregion
    }


}
