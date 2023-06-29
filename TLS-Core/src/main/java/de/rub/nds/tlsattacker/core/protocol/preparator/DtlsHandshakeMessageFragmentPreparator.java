/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentPreparator
        extends HandshakeMessagePreparator<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    private DtlsHandshakeMessageFragment msg;

    public DtlsHandshakeMessageFragmentPreparator(
            Chooser chooser, DtlsHandshakeMessageFragment message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        prepareHandshakeType(msg);
        msg.setMessageContent(msg.getFragmentContentConfig());
        msg.setLength(msg.getHandshakeMessageLengthConfig());
        msg.setMessageSequence(msg.getMessageSequenceConfig());
        msg.setFragmentOffset(msg.getOffsetConfig());
        msg.setFragmentLength(msg.getMessageContent().getValue().length);
    }

    private void prepareHandshakeType(DtlsHandshakeMessageFragment message) {
        HandshakeMessageType handshakeType = message.getHandshakeMessageTypeConfig();
        if (handshakeType == null) {
            handshakeType = msg.getHandshakeMessageType();
            if (handshakeType == null) {
                handshakeType = HandshakeMessageType.UNKNOWN;
            }
        }
        message.setType(handshakeType.getValue());
    }

    @Override
    protected void prepareMessageLength(int length) {
        LOGGER.debug(
                "Setting length of DtlsHandshakeMessage fragment to: "
                        + msg.getMessageContent().getValue().length);
        this.msg.setLength(msg.getMessageContent().getValue().length);
    }
}
