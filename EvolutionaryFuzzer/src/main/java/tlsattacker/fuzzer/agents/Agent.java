/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import java.io.File;
import tlsattacker.fuzzer.result.Result;
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
     *
     */
    protected ServerCertificateStructure keypair;

    /**
     * 
     * @param keypair
     */
    public Agent(ServerCertificateStructure keypair) {
	this.keypair = keypair;
    }

    /**
     * This method should be called, before the Fuzzingvector is sent to the
     * Application.
     * 
     * @param server
     */
    public abstract void applicationStart(TLSServer server);

    /**
     * This method should be called, after the Fuzzingvector is sent to the
     * Application.
     * 
     * @param server
     */
    public abstract void applicationStop(TLSServer server);

    /**
     * This method is used to receive the Results of the current Fuzzingvector
     * 
     * @param branchTrace
     *            File containing the Branch Information
     * @param vector
     * @param trace
     *            Workflowtrace which was executed (Fuzzingvector)
     * @param executedTrace
     * @return Result Object which contains all Information of the executed
     *         Fuzzingvector.
     */
    public abstract Result collectResults(File branchTrace, TestVector vector);
}
