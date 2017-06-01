/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class ProtocolMessagePreparator<T extends ProtocolMessage> extends Preparator<T> {

    private final ProtocolMessage message;

    public ProtocolMessagePreparator(TlsContext context, T message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public final void prepare() {
        prepareProtocolMessageContents();
    }

    protected abstract void prepareProtocolMessageContents();

    public void prepareAfterParse() {
    }
}
