/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageHandler<MessageT extends ProtocolMessage>
        implements Handler<MessageT> {

    protected static final Logger LOGGER = LogManager.getLogger();
    /** context */
    protected final TlsContext tlsContext;

    public ProtocolMessageHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    /**
     * Performs additional preparations after parsing the message (e.g. ESNI decryption/parsing).
     *
     * @param message
     */
    public void prepareAfterParse(MessageT message) {}

    public void updateDigest(ProtocolMessage message, boolean goingToBeSent) {
        if (!(message instanceof HandshakeMessage)) {
            return;
        }
        HandshakeMessage handshakeMessage = (HandshakeMessage) message;

        if (!handshakeMessage.getIncludeInDigest()) {
            return;
        }

        // DTLS 1.0 and 1.2 include fragment offsets in the digest, DTLS 1.3 does not
        if (tlsContext.getChooser().getSelectedProtocolVersion() == ProtocolVersion.DTLS10_DRAFT
                || tlsContext.getChooser().getSelectedProtocolVersion() == ProtocolVersion.DTLS10
                || tlsContext.getChooser().getSelectedProtocolVersion() == ProtocolVersion.DTLS12) {
            DtlsHandshakeMessageFragment fragment =
                    tlsContext
                            .getDtlsFragmentLayer()
                            .wrapInSingleFragment(tlsContext, handshakeMessage, goingToBeSent);
            tlsContext.getDigest().append(fragment.getCompleteResultingMessage().getValue());
        } else {
            tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
        }
        LOGGER.debug("Included in digest: " + message.toCompactString());
    }

    public void adjustContextAfterSerialize(MessageT message) {}
}
