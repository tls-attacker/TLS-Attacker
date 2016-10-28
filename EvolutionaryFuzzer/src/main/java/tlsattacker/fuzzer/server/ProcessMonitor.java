/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.server;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A Processmonitor which can tell you, when a command has finished in a non
 * blocking way. //TODO Rename
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProcessMonitor implements Runnable {

    /**
     * Creates a new ProcessMonitor for a Process
     * 
     * @param proc
     *            Process that should be monitored
     * @return new ProcessMonitor Object
     */
    public static ProcessMonitor create(Process proc) {
	ProcessMonitor procMon = new ProcessMonitor(proc);
	Thread t = new Thread(procMon);
	t.setName("Process Monitor Thread");
	t.start();

	return procMon;
    }

    /**
     * Process to monitor
     */

    private final Process process;

    /**
     * If the Process has completed execution
     */
    private volatile boolean completed;

    /**
     * Private Constructor, Objects should be created with the createProcMon
     * Method
     * 
     * @param p Process to monitor
     */
    private ProcessMonitor(Process p) {
	process = p;
    }

    /**
     * Returns true, if the Process is finished
     * 
     * @return If the process is Completed
     */
    public boolean isComplete() {
	return completed;
    }

    /**
     * Starts the Process monitor
     */
    @Override
    public void run() {
	try {
	    process.waitFor();
	    completed = true;
	} catch (InterruptedException ex) {
	    LOG.log(Level.WARNING, "Processmonitor received an InterruptedException!");
	}
    }
    
    private static final Logger LOG = Logger.getLogger(ProcessMonitor.class.getName());
}
