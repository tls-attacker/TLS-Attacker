/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * This Class represents a single Instance of an Implementation. The
 * Implementation can be started and restarted.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSServer
{

    private final Process p = null;
    private boolean free = true;
    private final String ip;

    private final int port;
    private int id = -1;
    private final String restartServerCommand;
    private boolean exited = false;
    private String accepted;
    private File traces; //Temporary Folder which contains currently executed traces
    private File crashedFolder; //Contains Traces which crashed the Implementation
    private File timeoutFolder; //Contains Traces which timedout
    private File goodTracesFolder; //Contains Traces which look promising
    private File faultyFolder; //Contains Traces which caused an exception on our end

    private ProcMon procmon = null;

    /**
     * Returns a Folder in which the Agent saves the Traces
     *
     * @return Folder in which the Agent saves the Traces
     */
    public File getTracesFolder()
    {
        return traces;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that crashed the
     * Implementation
     *
     * @return Folder which contains the WorkflowTraces that crashed the
     * Implementation
     */
    public File getCrashedFolder()
    {
        return crashedFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that timedout the
     * Implementation
     *
     * @return Folder which contains the WorkflowTraces that crashed the
     * Implementation
     */
    public File getTimeoutFolder()
    {
        return timeoutFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that looked promising
     *
     * @return Folder which contains the WorkflowTraces that crashed the
     * Implementation
     */
    public File getGoodTracesFolder()
    {
        return goodTracesFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that threw an
     * Exception on our end.
     *
     * @return Folder which contains the WorkflowTraces that crashed the
     * Implementation
     */
    public File getFaultyFolder()
    {
        return faultyFolder;
    }

    /**
     * Creates a new TLSServer. TLSServers should be used in the
     * TLSServerManager
     *
     * @param ip The IP of the Implementation
     * @param port The Port of the Implementation
     * @param restartServerCommand The command which should be executed to start
     * the Server
     * @param accepted The String which the Server prints to the console when
     * the Server is fully started
     */
    public TLSServer(String ip, int port, String restartServerCommand, String accepted, String outputFolder)
    {
        this.ip = ip;
        this.port = port;
        this.restartServerCommand = restartServerCommand;
        this.accepted = accepted;
        this.crashedFolder = new File(outputFolder + "crash/");
        this.faultyFolder = new File(outputFolder + "faulty/");
        this.goodTracesFolder = new File(outputFolder + "good/");
        this.traces = new File(outputFolder + "traces/");
        this.timeoutFolder = new File(outputFolder + "timeout/");
        if(!crashedFolder.exists()&&!crashedFolder.mkdirs())
        {
            throw new RuntimeException("Could not Create Output Folder!");
        }
        if(!faultyFolder.exists()&&!faultyFolder.mkdirs())
        {
            throw new RuntimeException("Could not Create Output Folder!");
        }
        if(!goodTracesFolder.exists()&&!goodTracesFolder.mkdirs())
        {
            throw new RuntimeException("Could not Create Output Folder!");
        }
        if(!traces.exists()&&!traces.mkdirs())
        {
            throw new RuntimeException("Could not Create Output Folder!");
        }
        if(!timeoutFolder.exists()&&!timeoutFolder.mkdirs())
        {
            throw new RuntimeException("Could not Create Output Folder!");
        }
    }

    /**
     * Returns the IP of the Server
     *
     * @return IP of the Server
     */
    public String getIp()
    {
        return ip;
    }

    /**
     * Returns the Port of the Server
     *
     * @return Port of the Server
     */
    public int getPort()
    {
        return port;
    }

    /**
     * Marks this Server. A Marked Server is currently used by the Fuzzer. A
     * Server should not be marked twice.
     */
    public synchronized void occupie()
    {
        if (this.free == false)
        {
            throw new IllegalStateException("Trying to occupie an already occupied Server");
        }
        this.free = false;
    }

    /**
     * Returns True if the Server is currently free to use
     *
     * @return True if the Server is currently free to use
     */
    public synchronized boolean isFree()
    {
        return free;
    }

    /**
     * Releases an occupied Server, so that it can be used further for other
     * Testvectors
     */
    public synchronized void release()
    {
        if (this.free == true)
        {
            throw new IllegalStateException("Trying to release an already released Server");
        }
        this.free = true;
    }

    /**
     * Starts the Server by executing the restart Server command
     */
    public synchronized void start()
    {

        //You have to ooccupie a Server to start it
        if (!this.isFree())
        {
            exited = false;
            if (p != null)
            {
                p.destroy();
            }
            restart();
        }
        else
        {
            throw new IllegalStateException("Cant start a not marked Server. Occupie it first!");
        }
    }

    /**
     * Restarts the Server by executing the restart Server command
     */
    public synchronized void restart()
    {
        if (!this.isFree())
        {
            exited = false;
            if (p != null)
            {
                p.destroy();
            }
            try
            {
                id = LogFileIDManager.getInstance().getID();
                String command = restartServerCommand.replace("[id]", "" + id);
                // System.out.println(command);

                Runtime rt = Runtime.getRuntime();
                Process proc = rt.exec(command);

                // any error message?
                StreamGobbler errorGobbler = new StreamGobbler(proc.getErrorStream(), "ERR", accepted);

                // any output?
                StreamGobbler outputGobbler = new StreamGobbler(proc.getInputStream(), "OUT", accepted);

                // kick them off
                errorGobbler.start();
                outputGobbler.start();
                procmon = ProcMon.create(proc);
                while (!outputGobbler.accepted())
                {

                }
                //TODO fix for other implementations

                //TODO Error 
                // System.out.println("ExitValue: " + exitVal);
            }
            catch (IOException t)
            {
                t.printStackTrace();
            }
        }
        else
        {
            throw new IllegalStateException("Cant restart a not marked Server. Occupie it first!");
        }

    }

    /**
     * Returns True if the Process the Server started has exited
     *
     * @return True if the Process the Server started has exited
     */
    public synchronized boolean exited()
    {
        if (procmon == null)
        {
            throw new IllegalStateException("Server not yet Started!");
        }
        else
        {
            return procmon.isComplete();
        }

    }

    /**
     * Returns the ID assigned to the currently started Server, the ID changes
     * after every restart
     *
     * @returnID assigned to the currently started Server
     */
    public synchronized int getID()
    {
        return id;
    }
    private static final Logger LOG = Logger.getLogger(TLSServer.class.getName());

}
