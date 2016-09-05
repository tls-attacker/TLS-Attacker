/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Server;

import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import Exceptions.TimeoutException;
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
    private String accepted;
    private StreamGobbler errorGobbler;
    private StreamGobbler outputGobbler;
    // our end

    private ProcMon procmon = null;

    public TLSServer() {
	ip = null;
	port = 0;
	restartServerCommand = null;
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
     */
    public TLSServer(String ip, int port, String restartServerCommand, String accepted) {
	this.ip = ip;
	this.port = port;
	this.restartServerCommand = restartServerCommand;
	this.accepted = accepted;
    }

    public String getAccepted() {
	return accepted;
    }

    public String getRestartServerCommand() {
	return restartServerCommand;
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
    public synchronized void start(String prefix, File certificateFile, File keyFile) {

	// You have to ooccupie a Server to start it
	if (!this.isFree()) {
	    if (p != null) {
		stop();
	    }
	    restart(prefix, certificateFile, keyFile);
	} else {
	    throw new IllegalStateException("Cant start a not marked Server. Occupie it first!");
	}
    }

    /**
     * Restarts the Server by executing the restart Server command
     */
    public synchronized void restart(String prefix, File certificateFile, File keyFile) {
	if (!this.isFree()) {
	    if (p != null) {
		stop();
	    }
	    try {
		id = LogFileIDManager.getInstance().getID();
		String command = (prefix + restartServerCommand).replace("[id]", "" + id);
		command = command.replace("[output]", ConfigManager.getInstance().getConfig().getTracesFolder()
			.getAbsolutePath());
		command = command.replace("[port]", "" + port);
		command = command.replace("[cert]", "" + certificateFile.getAbsolutePath());
		command = command.replace("[key]", "" + keyFile.getAbsolutePath());
		LOG.log(Level.FINE, "Starting Server:" + command);
		long time = System.currentTimeMillis();
		Runtime rt = Runtime.getRuntime();
		p = rt.exec(command);

		// any error message?
		errorGobbler = new StreamGobbler(p.getErrorStream(), "ERR", accepted);

		// any output?
		outputGobbler = new StreamGobbler(p.getInputStream(), "OUT", accepted);

		// kick them off
		errorGobbler.start();
		outputGobbler.start();
		procmon = ProcMon.create(p);
		while (!outputGobbler.accepted()) {

		    try {
			Thread.sleep(50);
		    } catch (InterruptedException ex) {
			Logger.getLogger(TLSServer.class.getName()).log(Level.SEVERE, null, ex);
		    }
		    if (System.currentTimeMillis() - time >= 60000) {
			throw new TimeoutException("Timeout in StreamGobler, Server never finished starting");
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
		+ restartServerCommand + ", accepted=" + accepted + '}';
    }

    /**
     * Stops the Server process
     */
    public void stop() {
	try {
	    if (p != null) {
		p.destroy();
		p.waitFor();
	    }
	} catch (Exception E) {
	    E.printStackTrace();
	}
    }

}
