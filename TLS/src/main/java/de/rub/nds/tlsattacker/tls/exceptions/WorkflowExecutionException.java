/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.exceptions;

/**
 * Thrown when problems by in the TLS workflow appear.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WorkflowExecutionException extends RuntimeException {

    public WorkflowExecutionException() {
	super();
    }

    public WorkflowExecutionException(String message) {
	super(message);
    }

    public WorkflowExecutionException(String message, Throwable t) {
	super(message, t);
    }
}
