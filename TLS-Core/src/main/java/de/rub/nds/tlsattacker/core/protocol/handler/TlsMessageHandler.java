/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.dtls.MessageFragmenter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @param <MessageT>
 * The ProtocolMessage that should be handled
 */
public abstract class TlsMessageHandler<MessageT extends TlsMessage> extends ProtocolMessageHandler<MessageT> {

    /**
     * @param tlsContext
     * The Context which should be Adjusted with this Handler
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
                    new MessageFragmenter(tlsContext.getConfig().getDtlsMaximumFragmentLength()).wrapInSingleFragment(
                            handshakeMessage, tlsContext);
            tlsContext.getDigest().append(fragment.getCompleteResultingMessage().getValue());
        } else {
            tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
        }
        LOGGER.debug("Included in digest: " + message.toCompactString());
    }
}
