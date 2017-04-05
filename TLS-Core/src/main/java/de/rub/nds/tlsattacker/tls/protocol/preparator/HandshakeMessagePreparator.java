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

    private HandshakeMessageSerializer serializer;
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
        serializer = (HandshakeMessageSerializer) msg.getHandler(context).getSerializer(msg);

        prepareMessageLength(serializer.serializeHandshakeMessageContent().length);
        if (isDTLS()) {
            prepareFragmentLenth(msg);
            prepareFragmentOffset(msg);
            prepareMessageSeq(msg);
        }
        prepareMessageType(msg.getHandshakeMessageType());
    }

    protected abstract void prepareHandshakeMessageContents();

    private void prepareFragmentLenth(HandshakeMessage msg) {
        msg.setFragmentLength(serializer.serializeHandshakeMessageContent().length);
        LOGGER.debug("FragmentLength: " + msg.getFragmentLength().getValue());
    }

    private void prepareFragmentOffset(HandshakeMessage msg) {
        msg.setFragmentOffset(0);
        LOGGER.debug("FragmentOffset: " + msg.getFragmentOffset().getValue());
    }

    private void prepareMessageSeq(HandshakeMessage msg) {
        msg.setMessageSeq(context.getSequenceNumber());
        LOGGER.debug("MessageSeq: " + msg.getMessageSeq().getValue());
    }

    private boolean isDTLS() {
        return context.getSelectedProtocolVersion().isDTLS();
    }
}
