/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.TestVectorResult;

/**
 * The Analyzer class which can analyze AgentResult objects
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Analyzer {

    /**
     * Analyzes a result
     * 
     * @param result
     *            AgentResult to analyze
     */
    public abstract void analyze(TestVectorResult result);

    /**
     * Generates a status report
     * 
     * @return Status report as a String
     */
    public abstract String getReport();
    
    /**
     * Returns the Branchtrace Object which contains the already seen
     * Edges and Vertices for Evolutionary Fuzzing. If somehow the Analyzer does
     * not collect Instrumentation output, it returns an empty BranchTrace
     * @return BranchTrace containing all seen Edges and Vertices
     */
    public abstract BranchTrace getBranchTrace();
}
