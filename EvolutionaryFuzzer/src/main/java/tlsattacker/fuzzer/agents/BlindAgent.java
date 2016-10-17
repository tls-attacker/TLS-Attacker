/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import tlsattacker.fuzzer.agents.Agent;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.config.ServerCertificateKey;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An Agent implemented with the modified Binary Instrumentation used by
 * American Fuzzy Lop
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BlindAgent extends Agent {

    private static final Logger LOG = Logger.getLogger(BlindAgent.class.getName());

    public static final String optionName = "BLIND";
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

    private final String prefix = "";

    /**
     * Default Constructor
     */
    public BlindAgent(ServerCertificateStructure keypair) {
	super(keypair);
	timeout = false;
	crash = false;
    }

    @Override
    public void applicationStart(TLSServer server) {
	if (running) {
	    throw new IllegalStateException("Cannot start a running Agent");
	}
	startTime = System.currentTimeMillis();
	running = true;
	server.start(prefix, keypair.getCertificateFile(), keypair.getKeyFile());
    }

    @Override
    public void applicationStop(TLSServer server) {
	if (!running) {
	    throw new IllegalStateException("Cannot stop a stopped Agent");
	}
	stopTime = System.currentTimeMillis();
	running = false;
	if (!server.serverIsRunning()) {
	    crash = true;
	}
	server.stop();
    }

    @Override
    public Result collectResults(File branchTrace, TestVector vector) {
	if (running) {
	    throw new IllegalStateException("Can't collect Results, Agent still running!");
	}

	BranchTrace t = new BranchTrace();

	Result result = new Result(crash, timeout, startTime, stopTime, t, vector, LogFileIDManager.getInstance()
		.getFilename());

	return result;
    }

}
