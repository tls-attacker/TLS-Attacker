/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.dtls.MessageFragmenter;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageHandler<MessageT extends TlsMessage> implements Handler<MessageT> {

    protected static final Logger LOGGER = LogManager.getLogger();
    /**
     * context
     */
    protected final Context context;

    public ProtocolMessageHandler(Context context) {
        this.context = context;
    }

    /**
     * Performs additional preparations after parsing the message (e.g. ESNI decryption/parsing).
     *
     * @param message
     */
    public void prepareAfterParse(MessageT message) {
    }

    public void updateDigest(TlsMessage message) {
        if (!(message instanceof HandshakeMessage)) {
            return;
        }

        HandshakeMessage handshakeMessage = (HandshakeMessage) message;

        if (!handshakeMessage.getIncludeInDigest()) {
            return;
        }

        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            DtlsHandshakeMessageFragment fragment =
                MessageFragmenter.wrapInSingleFragment(handshakeMessage, context);
            context.getDigest().append(fragment.getCompleteResultingMessage().getValue());
        } else {
            context.getDigest().append(message.getCompleteResultingMessage().getValue());
        }
        LOGGER.debug("Included in digest: " + message.toCompactString());
    }

    public void adjustContextAfterSerialize(MessageT message) {
    }

}
