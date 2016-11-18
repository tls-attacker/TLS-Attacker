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
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * Agents are Applications which monitor the behavior of the Fuzzed program.
 * Different Applications might require different Kinds of Agents. For Example a
 * binary Program needs a different Agent than a Java Programm, since the
 * controlflow of the Program is differently recorded. Other Programms might
 * need a different method to track if the Target Programm has crashed. The
 * Agent itself does not execute the Fuzzingvector.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Agent {

    /**
     * The server certificate key pair the agent should start the server with
     */
    protected ServerCertificateStructure keypair;
    /**
     * Is a fuzzing Progress Running?
     */
    protected boolean running = false;

    /**
     * Start time of the last TestVector
     */
    protected long startTime;

    /**
     * End time of the last TestVector
     */
    protected long stopTime;

    /**
     * If the application did timeout
     */
    protected boolean timeout;

    /**
     * If the application did crash
     */
    protected boolean crash;

    /**
     * The TLSServer the Agent should use
     */
    protected final TLSServer server;

    /**
     * Default Constructor
     * 
     * @param keypair
     *            The server certificate key pair the agent should start the
     *            server with
     * @param server
     *            The TLSServer the Agent should use
     */
    public Agent(ServerCertificateStructure keypair, TLSServer server) {
        this.keypair = keypair;
        this.server = server;
    }

    /**
     * This method should be called, before the TestVector is sent to the
     * application.
     */
    public abstract void applicationStart();

    /**
     * This method should be called, after the TestVector is sent to the
     * application.
     */
    public abstract void applicationStop();

    /**
     * This method is used to receive the Results of the current TestVector
     * 
     * @param branchTrace
     *            File containing the Branch Information
     * @param vector
     *            The TestVector that was executed.
     * @return AgentResult Object which contains all Information of the executed
     *         TestVector.
     */
    public abstract AgentResult collectResults(File branchTrace, TestVector vector);
}
