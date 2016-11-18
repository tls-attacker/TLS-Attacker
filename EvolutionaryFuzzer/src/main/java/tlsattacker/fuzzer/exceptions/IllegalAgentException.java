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
 * Exception thrown when an undefined Agent is configured
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IllegalAgentException extends Exception {

    public IllegalAgentException(String string) {
        super(string);
    }

    private static final Logger LOG = Logger.getLogger(IllegalAgentException.class.getName());

}
