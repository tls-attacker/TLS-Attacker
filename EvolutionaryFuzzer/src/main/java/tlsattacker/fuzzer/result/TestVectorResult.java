/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.result;

import java.util.LinkedList;
import java.util.List;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 *
 * @author ic0ns
 */
public class TestVectorResult {
    
    private final List<AgentResult> agentResults;
    private final TestVector testVector;
    
    public TestVectorResult(TestVector testVector, AgentResult result)
    {
        this.agentResults = new LinkedList<>();
        this.agentResults.add(result);
        this.testVector = testVector;
    }
    
    public TestVectorResult(TestVector testVector, List<AgentResult> agentResults)
    {
        this.agentResults = agentResults;
        this.testVector = testVector;
    }

    public List<AgentResult> getAgentResults() {
        return agentResults;
    }

    public TestVector getTestVector() {
        return testVector;
    }
}
