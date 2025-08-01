/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.dtls.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageHandler<MessageT extends ProtocolMessage>
        extends Handler<MessageT> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final TlsContext tlsContext;

    public ProtocolMessageHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public void updateDigest(ProtocolMessage message, boolean goingToBeSent) {
        if (!(message instanceof HandshakeMessage)) {
            return;
        }
        HandshakeMessage handshakeMessage = (HandshakeMessage) message;

        if (!handshakeMessage.getIncludeInDigest()) {
            return;
        }

        ProtocolVersion version = tlsContext.getChooser().getSelectedProtocolVersion();
        if (version == ProtocolVersion.DTLS10 || version == ProtocolVersion.DTLS12) {
            DtlsHandshakeMessageFragment fragment =
                    tlsContext
                            .getDtlsFragmentLayer()
                            .wrapInSingleFragment(
                                    tlsContext.getContext(), handshakeMessage, goingToBeSent);
            tlsContext.getDigest().append(fragment.getCompleteResultingMessage().getValue());
        } else {
            tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
        }
        LOGGER.debug("Included in digest: {}", message.toCompactString());
    }

    public void adjustContextAfterSerialize(MessageT message) {}

    public void adjustContextBeforeParse(MessageT message) {}

    public void adjustContextAfterParse(MessageT message) {}

    public void adjustContextAfterPrepare(MessageT message) {}

    public void adjustContextBeforePrepare(MessageT message) {}
}
