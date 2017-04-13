/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ServerHelloPreparator extends ProtocolMessagePreparator {

    private final SSL2ServerHelloMessage message;

    public SSL2ServerHelloPreparator(SSL2ServerHelloMessage message, TlsContext tlsContext) {
        super(tlsContext, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        throw new UnsupportedOperationException("Not supported Yet");
    }
}
