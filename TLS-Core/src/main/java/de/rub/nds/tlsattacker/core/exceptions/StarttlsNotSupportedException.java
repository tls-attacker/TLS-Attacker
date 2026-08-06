/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.exceptions;

import de.rub.nds.protocol.exception.WorkflowExecutionException;

/**
 * Thrown when a server definitively refuses a STARTTLS upgrade, for example by answering the
 * upgrade command with a permanent error status.
 *
 * <p>This is a deterministic outcome rather than a transient failure: the server will refuse
 * identically on every attempt. Task runners therefore treat it as a terminal result and do not
 * re-execute the workflow, unlike the generic {@link WorkflowExecutionException}.
 */
public class StarttlsNotSupportedException extends WorkflowExecutionException {

    public StarttlsNotSupportedException() {
        super();
    }

    public StarttlsNotSupportedException(String message) {
        super(message);
    }

    public StarttlsNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
