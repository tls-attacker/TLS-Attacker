/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * @param <T>
 *            The ProtocolMessage that should be prepared
 */
public abstract class ProtocolMessagePreparator<T extends ProtocolMessage> extends Preparator<T> {

    private final ProtocolMessage message;

    public ProtocolMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public final void prepare() {
        prepareProtocolMessageContents();
    }

    protected abstract void prepareProtocolMessageContents();

    /**
     * If clientMode is active, the prepareAfterParse method will compute all
     * the values as though the client parsed this Method. This is mostly only
     * useful if you are reparsing or doing something really crazy. For any
     * normal use case this should be set to false;
     *
     * @param clientMode
     */
    public void prepareAfterParse(boolean clientMode) {
    }
}
