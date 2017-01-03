/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import java.io.File;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * An Agent implemented with the modified Binary Instrumentation used by
 * American Fuzzy Lop
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BlindAgent extends Agent {

    /**
     * The name of the Agent when referred by command line
     */
    public static final String optionName = "BLIND";

    /**
     * Default Constructor
     * 
     * @param keypair
     *            Server certificate key pair the agent should start the server
     *            with.
     */
    public BlindAgent(ServerCertificateStructure keypair, TLSServer server) {
        super(keypair, server);
        timeout = false;
        crash = false;
    }

    @Override
    public void applicationStart() {
        if (running) {
            throw new IllegalStateException("Cannot start a running Agent");
        }
        startTime = System.currentTimeMillis();
        running = true;
        server.start("", keypair.getCertificateFile(), keypair.getKeyFile());
    }

    @Override
    public void applicationStop() {
        if (!running) {
            throw new IllegalStateException("Cannot stop a stopped Agent");
        }
        stopTime = System.currentTimeMillis();
        running = false;
        if (!server.serverHasBooted()) {
            crash = true;
        }
        server.stop();
    }

    @Override
    public AgentResult collectResults(File branchTrace, TestVector vector) {
        if (running) {
            throw new IllegalStateException("Can't collect Results, Agent still running!");
        }

        BranchTrace t = new BranchTrace();

        AgentResult result = new AgentResult(crash, timeout, startTime, stopTime, t, vector, LogFileIDManager
                .getInstance().getFilename(), server);

        return result;
    }

}
