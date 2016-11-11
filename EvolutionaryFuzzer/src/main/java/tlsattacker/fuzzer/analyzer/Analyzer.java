/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.result.Result;

/**
 * The Analyzer class which can analyze Result objects
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Analyzer {

    /**
     * Analyzes a result
     * 
     * @param result
     *            Result to analyze
     */
    public abstract void analyze(Result result);

    /**
     * Generates a status report
     * 
     * @return Status report as a String
     */
    public abstract String getReport();
}
