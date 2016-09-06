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
 * blocking way. //TODO got this tool from the internet, do i need to mark it?
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProcMon implements Runnable {
    private static final Logger LOG = Logger.getLogger(ProcMon.class.getName());

    /**
     * Creates a new ProcessMonitor for a Process
     * 
     * @param proc
     *            Process that should be monitored
     * @return new ProcessMonitor Object
     */
    public static ProcMon create(Process proc) {
	ProcMon procMon = new ProcMon(proc);
	Thread t = new Thread(procMon);
	t.setName("Process Monitor Thread");
	t.start();

	return procMon;
    }

    //

    private final Process _proc;
    private volatile boolean _complete;

    /**
     * Private Constructor, Objects should be created with the createProcMon
     * Method
     * 
     * @param p
     */
    private ProcMon(Process p) {
	_proc = p;
    }

    /**
     * Returns true, if the Process is finished
     * 
     * @return If the process is Completed
     */
    public boolean isComplete() {
	return _complete;
    }

    /**
     * Starts the Process monitor
     */
    @Override
    public void run() {
	try {
	    _proc.waitFor();
	    _complete = true;
	} catch (InterruptedException ex) {
	    LOG.log(Level.WARNING, "Processmonitor received an InterruptedException!");
	}
    }

}
