/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.LinkedList;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import java.util.logging.Logger;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;
import java.util.List;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.result.TestVectorResult;
import tlsattacker.fuzzer.server.ServerManager;

/**
 * This is implementation of the Executor executes a TestVector on a List of
 * TLSServers and returns a TestVectorResult object which contains an Agent
 * Result for each executed TLSServer.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MultiTLSExecutor extends Executor {

    /**
     * The name of the Executor when referred by command line
     */
    public static final String optionName = "multitls";

    /**
     * The TestVector that the executor should execute
     */
    private final TestVector testVector;

    /**
     * The TLSServers that the Executor should execute the TestVector on
     */
    private final List<TLSServer> servers;

    /**
     * Config object used
     */
    private final EvolutionaryFuzzerConfig config;

    /**
     * Constructor for the TLSExecutor
     * 
     * @param config
     *            Config that should be used
     * @param testVector
     *            TestVector that should be executed
     */
    public MultiTLSExecutor(EvolutionaryFuzzerConfig config, TestVector testVector) {
        this.testVector = testVector;
        this.servers = ServerManager.getInstance().occupieAllServers();
        this.config = config;
    }

    @Override
    public TestVectorResult call() throws Exception {
        List<AgentResult> agentResults = new LinkedList<>();
        for (TLSServer server : servers) {
            try {
                TestVector tempTestVector = (TestVector) UnoptimizedDeepCopy.copy(testVector);
                SingleTLSExecutor singleExecutor = new SingleTLSExecutor(config, tempTestVector, server);
                TestVectorResult result = singleExecutor.call();
                agentResults.addAll(result.getAgentResults());
            } catch (Exception E) {
                E.printStackTrace();
            }
        }
        return new TestVectorResult(testVector, agentResults);
    }

    private static final Logger LOG = Logger.getLogger(MultiTLSExecutor.class.getName());
}
