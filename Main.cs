/*
  
     =============================================================
      _____                      _        _____
     |  __ \                    | |      / ____|
     | |__) |___ _ __ ___   ___ | |_ ___| (___  _   _ _ __   ___
     |  _  // _ \ '_ ` _ \ / _ \| __/ _ \\___ \| | | | '_ \ / __|
     | | \ \  __/ | | | | | (_) | ||  __/____) | |_| | | | | (__
     |_|  \_\___|_| |_| |_|\___/ \__\___|_____/ \__, |_| |_|\___|
                                                 __/ |
                                                |___/

    =============================================================
                        RemoteSyncService 2023
                       Developed by Byte.Samurai
    =============================================================

    Forum Link :
    https://www.unknowncheats.me/forum/anti-cheat-bypass/583518-remotesync-file-transfer-service.html#post3750801

  
 */

// Imports
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

using Microsoft.Win32;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;
using System.Security.Principal;

// Namespace
namespace RemoteSyncCore
{
    // Entrypoint
    class Program
    {
        static void Main(string[] args)
        {
            // Check Opetions
            foreach (string arg in args)
            {
                // Run as Service
                if (arg == "--service")
                {
                    RemoteSyncServiceApp.AppMain(args);
                    break;
                }

                // Run as Shell
                if (arg == "--shell")
                {
                    RemoteSyncShellApp.AppMain(args);
                    break;
                }
            }

            Console.WriteLine("[Invalid Execution] Pass --service or --shell to run the application.");
        }
    }

    // Native Imports
    class NativeImports
    {
        // Imports
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        // Const Values
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        // Public API
        static public void SetConsoleVisibility(bool visibility)
        {
            // Hide the console window
            IntPtr hWnd = GetConsoleWindow();
            if (hWnd != IntPtr.Zero)
            {
                if (visibility)
                {
                    ShowWindow(hWnd, SW_SHOW);
                }
                else
                {
                    ShowWindow(hWnd, SW_HIDE);
                }
            }
        }
    }

    // RemoteSync Server
    class RemoteSyncServiceApp
    {
        // Globals Object
        private static TcpListener listener;
        private static NotifyIcon notifyIcon;
        private static Thread discoverThread;
        private static Thread listeningThread;
        private static Mutex AppMutex = null;

        // Const Objects
        private const string AppMutexName = "RemoteSyncApplicationInstance";

        // Internal Configs
        private static int dsicoveryInterval = 500;
        private static bool dumpFiles = false;
        private static int bufferSize = 4096;

        // Entrypoint
        public static void AppMain(string[] args)
        {
            // Check for Admin Access
            CheckForAdminAccess(args);

            // Check for Instance
            CheckForInstance();

            // Options
            bool noHeader = false;
            bool installOnSystem = false;
            bool removeFromSystem = false;

            // Check Opetions
            foreach (string arg in args)
            {
                if (arg == "--noheader")
                {
                    noHeader = true;
                    break;
                }

                if (arg == "--install")
                {
                    installOnSystem = true;
                    break;
                }

                if (arg == "--remove")
                {
                    if (installOnSystem != true)
                    {
                        removeFromSystem = true;
                    }
                    break;
                }
                if (arg == "--help")
                {
                    PrintHelp();
                    Environment.Exit(0);
                    break;
                }
            }

            // Print Banner
            PrintBanner();

            // Get the local IP address
            string localIP = GetLocalIPAddress();

            // Install/Uninstall the app for running at startup of windows
            if (installOnSystem) InstallOnSystemStartup();
            if (removeFromSystem) RemoveFromSystemStartup();

            // Start the server on a random unused port
            listener = new TcpListener(IPAddress.Parse(localIP), 0);
            listener.Start();
            Console.WriteLine("RemoteSync Server Started On {0}:{1}", localIP, ((IPEndPoint)listener.LocalEndpoint).Port);

            // Start the discovery broadcast
            discoverThread = new Thread(new ThreadStart(BroadcastDiscovery));
            discoverThread.IsBackground = true;
            discoverThread.Start();

            // No Header Option
            if (noHeader)
            {
                Console.WriteLine("RemoteSync Server Going Stealth Mode...");
                Thread.Sleep(500);
                NativeImports.SetConsoleVisibility(false);
            }

            // Spawn TCP Listening Thread
            listeningThread = new Thread(ListenerThread);
            listeningThread.Start();

            // Create Tray Icon
            CreateTrayIcon();

            // Run Application Message Loop
            Application.Run();
        }

        // Functions
        private static void ListenerThread()
        {
            // Listen for clients
            Console.WriteLine("RemoteSync Server Listening Clients...");
            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();

                // Spawn a thread to handle the client connection
                Thread clientThread = new Thread(new ParameterizedThreadStart(HandleClient));
                clientThread.IsBackground = true;
                clientThread.Start(client);
            }
        }
        private static void HandleClient(object clientObj)
        {
            if (dumpFiles) { DumpClientData(clientObj); return; }

            TcpClient client = (TcpClient)clientObj;
            NetworkStream stream = client.GetStream();

            try
            {
                // Read the target path from the network stream
                byte[] pathLengthBytes = new byte[4];
                stream.Read(pathLengthBytes, 0, pathLengthBytes.Length);
                int pathLength = BitConverter.ToInt32(pathLengthBytes, 0);

                byte[] pathBytes = new byte[pathLength];
                stream.Read(pathBytes, 0, pathBytes.Length);
                string targetPath = Encoding.UTF8.GetString(pathBytes);

                // Create Path if doesn't exist
                string directoryPath = Path.GetDirectoryName(targetPath);
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                // Delete file if exist
                if (File.Exists(targetPath)) File.Delete(targetPath);

                // Read the length of the file data sent by the client in bytes
                byte[] lengthBytes = new byte[4];
                stream.Read(lengthBytes, 0, lengthBytes.Length);
                int fileDataLength = BitConverter.ToInt32(lengthBytes, 0);

                Console.WriteLine("Syncing File at: {0}", targetPath);
                Console.WriteLine("Incoming File Size: {0} bytes", fileDataLength);

                // Create a FileStream to write the received file data to the target path
                using (FileStream fileStream = new FileStream(targetPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                {
                    // Set buffer size
                    int totalBytesRead = 0;

                    // Create a buffer to read data into
                    byte[] buffer = new byte[bufferSize];

                    // Read the file data from the stream and write it to disk
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, Math.Min(buffer.Length, fileDataLength - totalBytesRead))) > 0)
                    {
                        fileStream.Write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;

                        if (totalBytesRead >= fileDataLength) break;
                    }
                }

                Console.WriteLine("File received and saved successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error receiving file: {0}", ex.Message);
            }
            finally
            {
                Console.WriteLine("Incoming network stream closed.");
                client.Close();
            }
        }
        static string CalculateBroadcastAddress()
        {
            // Get all network interfaces
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            // Find the first interface that is up and has an IPv4 address
            UnicastIPAddressInformation ipInfo = null;
            foreach (NetworkInterface nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProps = nic.GetIPProperties();
                    if (ipProps != null)
                    {
                        foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                ipInfo = addr;
                                break;
                            }
                        }
                    }

                    if (ipInfo != null)
                    {
                        break;
                    }
                }
            }

            // If we couldn't find a suitable interface, return null
            if (ipInfo == null)
            {
                return null;
            }

            // Extract the IP address and subnet mask from the network interface information
            string ipAddress = ipInfo.Address.ToString();
            string subnetMask = ipInfo.IPv4Mask.ToString();

            // Parse the IP address and subnet mask into IPAddress objects
            IPAddress ip = IPAddress.Parse(ipAddress);
            IPAddress mask = IPAddress.Parse(subnetMask);

            // Convert the IP address and subnet mask to byte arrays
            byte[] ipBytes = ip.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();

            // Calculate the broadcast address by performing a bitwise OR operation on the IP address and inverted subnet mask
            byte[] broadcastBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                broadcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
            }

            // Construct an IPAddress object from the broadcast address byte array
            IPAddress broadcast = new IPAddress(broadcastBytes);

            // Return the broadcast address as a string
            return broadcast.ToString();
        }
        static void BroadcastDiscovery()
        {
            UdpClient udpClient = new UdpClient();

            // Prepare the discovery message
            string localIP = GetLocalIPAddress();
            string discoveryMessage = String.Format("RemoteSYNC|{0}|{1}", localIP, ((IPEndPoint)listener.LocalEndpoint).Port);
            byte[] discoveryBytes = System.Text.Encoding.ASCII.GetBytes(discoveryMessage);

            // Get the broadcast address and port
            string broadcastAddress = CalculateBroadcastAddress();
            int port = 8843;

            while (true)
            {
                try
                {
                    // Send the discovery message on the broadcast address and port
                    udpClient.Send(discoveryBytes, discoveryBytes.Length, broadcastAddress, port);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error broadcasting discovery: {0}", ex.Message);
                }
                Thread.Sleep(dsicoveryInterval);
            }
        }
        static string GetLocalIPAddress()
        {
            string localIP = "";
            foreach (IPAddress address in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    localIP = address.ToString();
                    break;
                }
            }
            return localIP;
        }
        static void CreateTrayIcon()
        {
            // Create a new NotifyIcon object
            notifyIcon = new NotifyIcon();

            // Set the icon image for the tray icon
            string exePath = System.Reflection.Assembly.GetEntryAssembly().Location;
            notifyIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);

            // Set the tooltip text for the tray icon
            notifyIcon.Text = "RemoteSync Service is Running";

            // Add a context menu to the tray icon with "Show Log..." and "Exit" menu items
            ContextMenuStrip contextMenu = new ContextMenuStrip();
            ToolStripMenuItem showLogMenuItem = new ToolStripMenuItem("Show Log...");
            ToolStripMenuItem exitMenuItem = new ToolStripMenuItem("Exit");
            contextMenu.Items.Add(showLogMenuItem);
            contextMenu.Items.Add(exitMenuItem);
            notifyIcon.ContextMenuStrip = contextMenu;

            // Attach event handlers for the menu items
            showLogMenuItem.Click += ShowLogMenuItem_Click;
            exitMenuItem.Click += ExitMenuItem_Click;

            // Show the tray icon
            notifyIcon.Visible = true;
        }
        static void InstallOnSystemStartup()
        {
            string appName = Assembly.GetExecutingAssembly().Location;
            RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

            if (key.GetValue("AppSync Service") == null)
            {
                key.SetValue("AppSync Service", $"\"{appName}\" --noheader");
                Console.WriteLine("RemoteSync Server Installed on System Startup!");
            }
            else
            {
                Console.WriteLine("RemoteSync Server is Already Installed on System Startup.");
            }
        }
        static void RemoveFromSystemStartup()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

            if (key.GetValue("AppSync Service") != null)
            {
                key.DeleteValue("AppSync Service");
                Console.WriteLine("RemoteSync Server Removed from System Startup!");
            }
            else
            {
                Console.WriteLine("RemoteSync Server is Not Installed on System Startup.");
            }
        }

        // Events
        private static void ShowLogMenuItem_Click(object sender, EventArgs e)
        {
            // Handle the Show Log... menu item click event here...
        }
        private static void ExitMenuItem_Click(object sender, EventArgs e)
        {
            // Remove the tray icon when you're done
            notifyIcon.Visible = false;
            notifyIcon.Dispose();

            Environment.Exit(0);
        }

        // Extra Tools / Helpers
        private static void CheckForAdminAccess(string[] args)
        {
            bool AdminAccess = IsRunningAsAdmin();

            // Debug Only
            // Console.WriteLine("Administrator Privileges : {0}", AdminAccess);

            if (!AdminAccess)
            {
                // Restart application with admin rights
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.UseShellExecute = true;
                startInfo.WorkingDirectory = Environment.CurrentDirectory;
                startInfo.FileName = Process.GetCurrentProcess().MainModule.FileName;
                startInfo.Verb = "runas";
                startInfo.Arguments = string.Join(" ", args);
                try
                {
                    Process.Start(startInfo);
                }
                catch (Exception)
                {
                    // User chose not to allow app to run as admin
                    Environment.Exit(-100);
                }

                // Quit current instance of the application
                Environment.Exit(-3);
            }
        }
        private static void CheckForInstance()
        {
            bool createdNew;
            AppMutex = new Mutex(true, AppMutexName, out createdNew);

            if (!createdNew)
            {
                // Another instance is already running, so exit gracefully
                Console.WriteLine("Another instance of the application is already running. Exiting...");
                Thread.Sleep(1000);
                Environment.Exit(-2);
            }
        }
        private static void PrintHelp()
        {
            Console.WriteLine($"---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---\n");
            Console.WriteLine($"  RemoteSync Help                                                                     ");
            Console.WriteLine($"\n---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---\n");
            Console.WriteLine($"  > Command                     > Description                                           ");
            Console.WriteLine($"\n---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---\n");
            Console.WriteLine($"  --noheader                    Run at hidden mode as background process                ");
            Console.WriteLine($"  --install                     Install the service on windows startup                  ");
            Console.WriteLine($"  --remove                      Uninstall the service from windows startup              ");
            Console.WriteLine($"\n---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---    ---");
        }
        private static void PrintBanner()
        {
            Console.Title = "RemoteSync Data Transfer Service by Byte.Samurai";
            string asciiArt = @"
=============================================================
  _____                      _        _____                  
 |  __ \                    | |      / ____|                 
 | |__) |___ _ __ ___   ___ | |_ ___| (___  _   _ _ __   ___ 
 |  _  // _ \ '_ ` _ \ / _ \| __/ _ \\___ \| | | | '_ \ / __|
 | | \ \  __/ | | | | | (_) | ||  __/____) | |_| | | | | (__ 
 |_|  \_\___|_| |_| |_|\___/ \__\___|_____/ \__, |_| |_|\___|
                                             __/ |           
                                            |___/            

=============================================================
                    RemoteSyncService 2023
                  Developed by Byte.Samurai
=============================================================
";
            Console.WriteLine(asciiArt);
        }
        private static bool IsRunningAsAdmin()
        {
            WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(windowsIdentity);

            return windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static void DumpClientData(object clientObj)
        {
            TcpClient client = (TcpClient)clientObj;
            NetworkStream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);

            try
            {
                // Dump stream to file "DumpStream.bin"
                string dumpPath = $"DumpStream_{clientObj.GetHashCode()}.bin";
                using (FileStream dumpStream = new FileStream(dumpPath, FileMode.Create))
                {
                    byte[] dumpBuffer = new byte[1024];
                    int dumpBytesRead;
                    while ((dumpBytesRead = stream.Read(dumpBuffer, 0, dumpBuffer.Length)) > 0)
                    {
                        dumpStream.Write(dumpBuffer, 0, dumpBytesRead);
                    }
                }

                Console.WriteLine("Incoming stream successfully dumped to file: {0}", dumpPath);

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error receiving file: {0}", ex.Message);
            }
            finally
            {
                client.Close();
            }
        }
    }

    // RemoteSync Client
    class RemoteSyncShellApp
    {
        // Const Data & Structs
        
        struct AppExitCodes
        {
            // For Visual Studio Post Build Only
            public const int UNKNOWN_ERROR = 1;
            public const int USER_ABORTED = 0;
            public const int FILE_SENT = 0;
            public const int FILE_SENT_AND_VALIDATED = 0;
            public const int FILE_CANNOT_BE_SEND = 1;
            public const int SERVER_NOT_FOUND = 1;
            public const int CONNECTION_FAILED = 1;
            public const int CANNOT_ACCESS_FILE = 1;
            public const int FILE_NOT_EXISTS = 1;
        }

        // Internal Configs
        private static int ReceiveTimeout = 5000;

        // Entrypoint
        public static void AppMain(string[] args)
        {
            Console.Title = "RemoteSync Data Transfer Shell by Byte.Samurai";

            // Parse the command line arguments
            string filePath = "";
            string targetPath = "";

            // Get Inputs
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-file":
                        filePath = args[++i];
                        break;

                    case "-targetpath":
                        targetPath = args[++i];
                        break;
                }
            }

            // Default Path
            if (targetPath == "") targetPath = "C:\\RemoteSyncData";

            // Validate Inputs
            if (filePath == "" || targetPath == "")
            {
                Console.WriteLine("Usage: RemoteSyncAMD64.exe -file \"targetFile.dll\" -targetpath \"C:\\TargetPath\"");
                Environment.Exit(AppExitCodes.USER_ABORTED);
                return;
            }

            // Discover the server
            string[] serverInfo = DiscoverServer();
            if (serverInfo == null)
            {
                Console.WriteLine("[ERROR] Could not find the server.");
                Environment.Exit(AppExitCodes.SERVER_NOT_FOUND);
                return;
            }

            // Parse Server Info
            string srv_hostname = serverInfo[1];
            int srv_port = Int32.Parse(serverInfo[2]);

            // Connect to the server and send the file
            TcpClient client = new TcpClient(srv_hostname, srv_port);
            NetworkStream stream = client.GetStream();

            try
            {
                // Prepare File Path
                targetPath = targetPath + "\\" + Path.GetFileName(filePath);
                // Console.WriteLine("[INFO] Syncing File ({0})...", Path.GetFileName(targetPath));

                // Send the target path to the server
                byte[] pathBytes = Encoding.UTF8.GetBytes(targetPath);
                byte[] pathLengthBytes = BitConverter.GetBytes(pathBytes.Length);
                stream.Write(pathLengthBytes, 0, pathLengthBytes.Length);
                stream.Write(pathBytes, 0, pathBytes.Length);

                // Send the file data to the server, Validate file
                if (!File.Exists(filePath))
                {
                    client.Close();
                    Console.WriteLine("[ERROR] File Not Exists!");
                    Environment.Exit(AppExitCodes.FILE_NOT_EXISTS);
                }

                // Read the file into memory
                byte[] fileData = null;
                try
                {
                    fileData = File.ReadAllBytes(filePath);
                }
                catch (Exception)
                {
                    client.Close();
                    Console.WriteLine("[ERROR] File Access Denied.");
                    Environment.Exit(AppExitCodes.CANNOT_ACCESS_FILE);
                }

                // Send the file data length to the server
                byte[] lengthBytes = BitConverter.GetBytes(fileData.Length);
                stream.Write(lengthBytes, 0, lengthBytes.Length);

                // Send the file data to the server
                stream.Write(fileData, 0, fileData.Length);

                Console.WriteLine("[SUCCESS] File ({0}) Synced Successfully.", Path.GetFileName(targetPath));
                client.Close();
                Environment.Exit(AppExitCodes.FILE_SENT);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] Sending File Failed With Following Error -> {0}", ex.Message);
                client.Close();
                Environment.Exit(AppExitCodes.FILE_CANNOT_BE_SEND);
            }

            Console.WriteLine("[ERROR] Unknown Error!");
            Environment.Exit(AppExitCodes.UNKNOWN_ERROR);
        }

        // Functions
        private static string[] DiscoverServer()
        {
            UdpClient udpClient = new UdpClient(8843);

            try
            {
                Console.WriteLine("[INFO] Searching for Server...");

                // Receive the discovery response from the server
                udpClient.Client.ReceiveTimeout = ReceiveTimeout;
                IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(CalculateBroadcastAddress()), 0);
                byte[] discoveryBytes = udpClient.Receive(ref endPoint);
                string discoveryMessage = Encoding.ASCII.GetString(discoveryBytes);
                string[] serverInfo = discoveryMessage.Split('|');
                if (serverInfo[0] == "RemoteSYNC")
                {
                    return serverInfo;
                }
                else
                {
                    return null;
                }
            }
            catch (SocketException)
            {
                return null;
            }
            finally
            {
                udpClient.Close();
            }
        }
        private static string CalculateBroadcastAddress()
        {
            // Get all network interfaces
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            // Find the first interface that is up and has an IPv4 address
            UnicastIPAddressInformation ipInfo = null;
            foreach (NetworkInterface nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProps = nic.GetIPProperties();
                    if (ipProps != null)
                    {
                        foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                ipInfo = addr;
                                break;
                            }
                        }
                    }

                    if (ipInfo != null)
                    {
                        break;
                    }
                }
            }

            // If we couldn't find a suitable interface, return null
            if (ipInfo == null)
            {
                return null;
            }

            // Extract the IP address and subnet mask from the network interface information
            string ipAddress = ipInfo.Address.ToString();
            string subnetMask = ipInfo.IPv4Mask.ToString();

            // Parse the IP address and subnet mask into IPAddress objects
            IPAddress ip = IPAddress.Parse(ipAddress);
            IPAddress mask = IPAddress.Parse(subnetMask);

            // Convert the IP address and subnet mask to byte arrays
            byte[] ipBytes = ip.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();

            // Calculate the broadcast address by performing a bitwise OR operation on the IP address and inverted subnet mask
            byte[] broadcastBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                broadcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
            }

            // Construct an IPAddress object from the broadcast address byte array
            IPAddress broadcast = new IPAddress(broadcastBytes);

            // Return the broadcast address as a string
            return broadcast.ToString();
        }
    }
}
