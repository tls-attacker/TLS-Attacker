/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.exceptions;

/**
 * Exception that indicates that the server did not start properly
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerDoesNotStartException extends RuntimeException {

    public ServerDoesNotStartException(String message) {
        super(message);
    }
}
