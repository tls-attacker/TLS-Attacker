/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agents;

import Agents.Agent;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.logging.Level;
import java.util.logging.Logger;
import Graphs.BranchTrace;
import Helper.LogFileIDManager;
import Result.Result;
import Server.TLSServer;

/**
 * An Agent implemented with the modified Binary Instrumentation used by
 * American Fuzzy Lop
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AFLAgent extends Agent {
    private static final Logger LOG = Logger.getLogger(AFLAgent.class.getName());

    // Is a fuzzing Progress Running?
    protected boolean running = false;
    // StartTime of the last Fuzzing Vektor
    protected long startTime;
    // StopTime of the last Fuzzing Vektor
    protected long stopTime;
    // If the Application did Timeout
    protected boolean timeout;
    // If the Application did Crash
    protected boolean crash;
    private final String prefix = "AFL/afl-showmap -m none -o [output]/[id] ";

    /**
     * Default Constructor
     */
    public AFLAgent() {
	timeout = false;
	crash = false;

    }

    @Override
    public void applicationStart(TLSServer server) {
	if (running) {
	    throw new IllegalStateException("Cannot start a running AFL Agent");
	}
	startTime = System.currentTimeMillis();
	running = true;
	server.start(prefix);
    }

    @Override
    public void applicationStop(TLSServer server) {
	if (!running) {
	    throw new IllegalStateException("Cannot stop a stopped AFL Agent");
	}
	stopTime = System.currentTimeMillis();
	running = false;
    }

    @Override
    public Result collectResults(File branchTrace, WorkflowTrace trace, WorkflowTrace executedTrace) {
	if (running) {
	    throw new IllegalStateException("Can't collect Results, Agent still running!");
	}

	String tail = tail(branchTrace);
	switch (tail) {
	    case "CRASH":
		LOG.log(Level.INFO, "Found a Crash!");
		crash = true;
		break;
	    case "TIMEOUT":
		LOG.log(Level.INFO, "Found a Timeout!");
		timeout = true;
		break;
	}
	BranchTrace t = new BranchTrace();
	try {
	    // TODO
	    t.merge(branchTrace);
	} catch (IOException ex) {
	    Logger.getLogger(AFLAgent.class.getName()).log(Level.SEVERE, null, ex);
	}

	Result result = new Result(crash, timeout, startTime, stopTime, t, trace, executedTrace, LogFileIDManager
		.getInstance().getFilename());

	return result;
    }

    private String tail(File file) {
	RandomAccessFile fileHandler = null;
	try {
	    fileHandler = new RandomAccessFile(file, "r");
	    long fileLength = fileHandler.length() - 1;
	    StringBuilder sb = new StringBuilder();

	    for (long filePointer = fileLength; filePointer != -1; filePointer--) {
		fileHandler.seek(filePointer);
		int readByte = fileHandler.readByte();

		if (readByte == 0xA) {
		    if (filePointer == fileLength) {
			continue;
		    }
		    break;

		} else if (readByte == 0xD) {
		    if (filePointer == fileLength - 1) {
			continue;
		    }
		    break;
		}

		sb.append((char) readByte);
	    }

	    String lastLine = sb.reverse().toString();
	    return lastLine;
	} catch (java.io.FileNotFoundException e) {
	    e.printStackTrace();
	    return null;
	} catch (java.io.IOException e) {
	    e.printStackTrace();
	    return null;
	} finally {
	    if (fileHandler != null) {
		try {
		    fileHandler.close();
		} catch (IOException e) {
		    /* ignore */
		}
	    }
	}
    }

}
