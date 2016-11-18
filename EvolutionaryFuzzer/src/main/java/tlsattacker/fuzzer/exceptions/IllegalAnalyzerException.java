/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.exceptions;

import java.util.logging.Logger;

/**
 * Exception thrown if an illegal Analyzer is selected
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IllegalAnalyzerException extends Exception {

    public IllegalAnalyzerException(String message) {
        super(message);
    }

    private static final Logger LOG = Logger.getLogger(IllegalAnalyzerException.class.getName());

}
