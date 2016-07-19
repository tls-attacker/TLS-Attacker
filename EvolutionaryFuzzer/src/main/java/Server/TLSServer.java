/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Server;

import Config.ConfigManager;
import Helper.LogFileIDManager;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This Class represents a single Instance of an Implementation. The
 * Implementation can be started and restarted.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public final class TLSServer {
    private static final Logger LOG = Logger.getLogger(TLSServer.class.getName());

    private Process p = null;
    private boolean free = true;
    private String ip;

    private int port;
    private int id = -1;
    private String restartServerCommand;
    private String outputFolder;
    private String accepted;
    private File traces; // Temporary Folder which contains currently executed
    // traces
    private File crashedFolder; // Contains Traces which crashed the
    // Implementation
    private File timeoutFolder; // Contains Traces which timedout
    private File goodTracesFolder; // Contains Traces which look promising
    private File faultyFolder; // Contains Traces which caused an exception on
    private StreamGobbler errorGobbler;
    private StreamGobbler outputGobbler;
    // our end

    private ProcMon procmon = null;

    public TLSServer() {
	ip = null;
	port = 0;
	restartServerCommand = null;
	outputFolder = null;
    }

    /**
     * Creates a new TLSServer. TLSServers should be used in the
     * TLSServerManager
     * 
     * @param ip
     *            The IP of the Implementation
     * @param port
     *            The Port of the Implementation
     * @param restartServerCommand
     *            The command which should be executed to start the Server
     * @param accepted
     *            The String which the Server prints to the console when the
     *            Server is fully started
     * @param outputFolder
     */
    public TLSServer(String ip, int port, String restartServerCommand, String accepted, String outputFolder) {
	this.outputFolder = outputFolder;
	this.ip = ip;
	this.port = port;
	this.restartServerCommand = restartServerCommand;
	this.accepted = accepted;
	this.setOutputFolder(outputFolder);
    }

    /**
     * Returns a Folder in which the Agent saves the Traces
     * 
     * @return Folder in which the Agent saves the Traces
     */
    public File getTracesFolder() {
	return traces;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that crashed the
     * Implementation
     * 
     * @return Folder which contains the WorkflowTraces that crashed the
     *         Implementation
     */
    public File getCrashedFolder() {
	return crashedFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that timedout the
     * Implementation
     * 
     * @return Folder which contains the WorkflowTraces that crashed the
     *         Implementation
     */
    public File getTimeoutFolder() {
	return timeoutFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that looked promising
     * 
     * @return Folder which contains the WorkflowTraces that crashed the
     *         Implementation
     */
    public File getGoodTracesFolder() {
	return goodTracesFolder;
    }

    /**
     * Returns a Folder which contains the WorkflowTraces that threw an
     * Exception on our end.
     * 
     * @return Folder which contains the WorkflowTraces that crashed the
     *         Implementation
     */
    public File getFaultyFolder() {
	return faultyFolder;
    }

    public String getOutputFolder() {
	return outputFolder;
    }

    public String getAccepted() {
	return accepted;
    }

    public String getRestartServerCommand() {
	return restartServerCommand;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
	this.crashedFolder = new File(outputFolder + "crash/");
	this.faultyFolder = new File(outputFolder + "faulty/");
	this.goodTracesFolder = new File(outputFolder + "good/");
	this.traces = new File(outputFolder + "traces/");
	this.timeoutFolder = new File(outputFolder + "timeout/");
	if (!crashedFolder.exists() && !crashedFolder.mkdirs()) {
	    throw new RuntimeException("Could not Create Output Folder!");
	}
	if (!faultyFolder.exists() && !faultyFolder.mkdirs()) {
	    throw new RuntimeException("Could not Create Output Folder!");
	}
	if (!goodTracesFolder.exists() && !goodTracesFolder.mkdirs()) {
	    throw new RuntimeException("Could not Create Output Folder!");
	}
	if (!traces.exists() && !traces.mkdirs()) {
	    throw new RuntimeException("Could not Create Output Folder!");
	}
	if (!timeoutFolder.exists() && !timeoutFolder.mkdirs()) {
	    throw new RuntimeException("Could not Create Output Folder!");
	}
    }

    /**
     * Returns the IP of the Server
     * 
     * @return IP of the Server
     */
    public String getIp() {
	return ip;
    }

    /**
     * Returns the Port of the Server
     * 
     * @return Port of the Server
     */
    public int getPort() {
	return port;
    }

    public void setIp(String ip) {
	this.ip = ip;
    }

    public void setPort(int port) {
	this.port = port;
    }

    public void setRestartServerCommand(String restartServerCommand) {
	this.restartServerCommand = restartServerCommand;
    }

    public void setAccepted(String accepted) {
	this.accepted = accepted;
    }

    /**
     * Marks this Server. A Marked Server is currently used by the Fuzzer. A
     * Server should not be marked twice.
     */
    public synchronized void occupie() {
	if (this.free == false) {
	    throw new IllegalStateException("Trying to occupie an already occupied Server");
	}
	this.free = false;
    }

    /**
     * Returns True if the Server is currently free to use
     * 
     * @return True if the Server is currently free to use
     */
    public synchronized boolean isFree() {
	return free;
    }

    /**
     * Releases an occupied Server, so that it can be used further for other
     * Testvectors
     */
    public synchronized void release() {
	if (this.free == true) {
	    throw new IllegalStateException("Trying to release an already released Server");
	}
	this.free = true;
    }

    /**
     * Starts the Server by executing the restart Server command
     */
    public synchronized void start(String prefix) {

	// You have to ooccupie a Server to start it
	if (!this.isFree()) {
	    if (p != null) {
		p.destroy();
	    }
	    restart(prefix);
	} else {
	    throw new IllegalStateException("Cant start a not marked Server. Occupie it first!");
	}
    }

    /**
     * Restarts the Server by executing the restart Server command
     */
    public synchronized void restart(String prefix) {
	if (!this.isFree()) {
	    if (p != null) {
		p.destroy();
	    }
	    try {
		id = LogFileIDManager.getInstance().getID();
		String command = (prefix + restartServerCommand).replace("[id]", "" + id);
		command = command.replace("[output]", traces.getAbsolutePath());
		command = command.replace("[port]", "" + port);
		// System.out.println(command);
		long time = System.currentTimeMillis();
		Runtime rt = Runtime.getRuntime();
		Process proc = rt.exec(command);

		// any error message?
		errorGobbler = new StreamGobbler(proc.getErrorStream(), "ERR", accepted);

		// any output?
		outputGobbler = new StreamGobbler(proc.getInputStream(), "OUT", accepted);

		// kick them off
		errorGobbler.start();
		outputGobbler.start();
		procmon = ProcMon.create(proc);
		while (!outputGobbler.accepted()) {

		    try {
			Thread.sleep(50);
		    } catch (InterruptedException ex) {
			Logger.getLogger(TLSServer.class.getName()).log(Level.SEVERE, null, ex);
		    }
		    if (System.currentTimeMillis() - time >= ConfigManager.getInstance().getConfig().getTimeout()) {
			throw new RuntimeException("Timeout in StreamGobler, Server never finished starting");
		    }
		}
	    } catch (IOException t) {
		t.printStackTrace();
	    }
	} else {
	    throw new IllegalStateException("Cant restart a not marked Server. Occupie it first!");
	}

    }

    public synchronized boolean serverIsRunning() {
	return outputGobbler != null && outputGobbler.accepted() && p != null;
    }

    /**
     * Returns True if the Process the Server started has exited
     * 
     * @return True if the Process the Server started has exited
     */
    public synchronized boolean exited() {
	if (procmon == null) {
	    throw new IllegalStateException("Server not yet Started!");
	} else {
	    return procmon.isComplete();
	}

    }

    /**
     * Returns the ID assigned to the currently started Server, the ID changes
     * after every restart
     * 
     * @returnID assigned to the currently started Server
     */
    public synchronized int getID() {
	return id;
    }

    @Override
    public String toString() {
	return "TLSServer{free=" + free + ", ip=" + ip + ", port=" + port + ", id=" + id + ", restartServerCommand="
		+ restartServerCommand + ", outputFolder=" + outputFolder + ", accepted=" + accepted + ", traces="
		+ traces + ", crashedFolder=" + crashedFolder + ", timeoutFolder=" + timeoutFolder
		+ ", goodTracesFolder=" + goodTracesFolder + ", faultyFolder=" + faultyFolder + '}';
    }

    /**
     * Stops the Server process
     */
    public void stop() {
	p.destroy();

    }

}
