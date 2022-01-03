/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.dtls.MessageFragmenter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.parser.TlsMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.TlsMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.TlsMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @param <MessageT>
 *                   The ProtocolMessage that should be handled
 */
public abstract class TlsMessageHandler<MessageT extends TlsMessage> extends ProtocolMessageHandler<MessageT> {

    /**
     * @param tlsContext
     *                   The Context which should be Adjusted with this Handler
     */
    public TlsMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    public void updateDigest(ProtocolMessage message) {
        if (!(message instanceof HandshakeMessage)) {
            return;
        }

        HandshakeMessage handshakeMessage = (HandshakeMessage) message;

        if (!handshakeMessage.getIncludeInDigest()) {
            return;
        }

        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            DtlsHandshakeMessageFragment fragment =
                MessageFragmenter.wrapInSingleFragment(handshakeMessage, tlsContext);
            tlsContext.getDigest().append(fragment.getCompleteResultingMessage().getValue());
        } else {
            tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
        }
        LOGGER.debug("Included in digest: " + message.toCompactString());
    }

    /**
     * Adjusts the TLS Context according to the received or sending ProtocolMessage
     *
     * @param message
     *                The Message for which this context should be adjusted
     */
    public abstract void adjustTLSContext(MessageT message);

    @Override
    public final void adjustContext(MessageT message) {
        adjustTLSContext(message);
    }

    public void adjustTlsContextAfterSerialize(MessageT message) {
    }

    @Override
    public abstract TlsMessageParser<MessageT> getParser(byte[] message, int pointer);

    @Override
    public abstract TlsMessagePreparator<MessageT> getPreparator(MessageT message);

    @Override
    public abstract TlsMessageSerializer<MessageT> getSerializer(MessageT message);
}
