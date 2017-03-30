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
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class HandshakeMessagePreparator<T extends HandshakeMessage> extends ProtocolMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final HandshakeMessage msg;

    public HandshakeMessagePreparator(TlsContext context, T message) {
        super(context, message);
        this.msg = message;
    }

    private void prepareMessageLength(int length) {
        msg.setLength(length);
        LOGGER.debug("Length: " + msg.getLength().getValue());
    }

    private void prepareMessageType(HandshakeMessageType type) {
        msg.setType(type.getValue());
        LOGGER.debug("Type: " + msg.getType().getValue());
    }

    @Override
    protected final void prepareProtocolMessageContents() {
        prepareHandshakeMessageContents();
        // Ugly but only temporary
        HandshakeMessageSerializer serializer = (HandshakeMessageSerializer) msg.getHandler(context).getSerializer(msg);

        prepareMessageLength(serializer.serializeHandshakeMessageContent().length);
        if (context.getSelectedProtocolVersion().isDTLS()) {
            msg.setFragmentLength(serializer.serializeHandshakeMessageContent().length);
            msg.setFragmentOffset(0);
            msg.setMessageSeq(context.getSequenceNumber()); //TODO refactor
        }
        prepareMessageType(msg.getHandshakeMessageType());
    }

    protected abstract void prepareHandshakeMessageContents();
}
