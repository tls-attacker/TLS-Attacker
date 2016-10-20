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
     *
     * @param result
     */
    public abstract void analyze(Result result);

    /**
     *
     * @return
     */
    public abstract String getReport();
}
