using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public static class Startup
{
    #region Private Fields
    private static bool m_initialized = false;
    //private static System.Threading.Thread workerThread = null;
    #endregion Private Fields

    /*
    ~Startup()
    {
        workerThread.Join();
    }
    */

    public static void WorkerThread()
    {
        MessageBox.Show("CLR Code Injected!", "McAfee Injector (minjector)");
        while (true) Thread.Sleep(100);
    }

    [STAThread]
    public static int EntryPoint(string args)
    {
        if (!m_initialized)
        {
            m_initialized = true;

            WorkerThread();
            //workerThread = new Thread(new ThreadStart(WorkerThread));
            //workerThread.Start();
        }

        return 0;
    }

}