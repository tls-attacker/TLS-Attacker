/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.exceptions;

/** Thrown when problems by in the TLS workflow appear. */
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

    public WorkflowExecutionException(Throwable throwable) {
        super(throwable);
    }
}
