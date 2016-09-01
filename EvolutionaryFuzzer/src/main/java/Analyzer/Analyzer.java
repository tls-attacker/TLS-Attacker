/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Result.Result;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Analyzer {
    public abstract void analyze(Result result);

    public abstract String getReport();
}
