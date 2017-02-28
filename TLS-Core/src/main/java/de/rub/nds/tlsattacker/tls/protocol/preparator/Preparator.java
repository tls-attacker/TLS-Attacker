/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class Preparator<T> {

    protected final TlsContext context;
    private final T object;

    public Preparator(TlsContext context, T object) {
        this.context = context;
        this.object = object;
    }

    public abstract void prepare();
}
