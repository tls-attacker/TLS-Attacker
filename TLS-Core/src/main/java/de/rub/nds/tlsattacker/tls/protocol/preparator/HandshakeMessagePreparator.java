/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class HandshakeMessagePreparator<T extends HandshakeMessage> extends ProtocolMessagePreparator<T> {

    private final HandshakeMessage message;

    public HandshakeMessagePreparator(TlsContext context, T message) {
        super(context, message);
        this.message = message;
    }

    private void prepareMessageLength(int length) {
        message.setLength(length);
    }

    private void prepareMessageType(HandshakeMessageType type) {
        message.setType(type.getValue());
    }

    @Override
    protected final void prepareProtocolMessageContents() {
        prepareHandshakeMessageContents();
        // Ugly but only temporary
        HandshakeMessageSerializer serializer = (HandshakeMessageSerializer) message.getSerializer();
        prepareMessageLength(serializer.serializeHandshakeMessageContent().length);
        prepareMessageType(message.getHandshakeMessageType());
    }

    protected abstract void prepareHandshakeMessageContents();
}
