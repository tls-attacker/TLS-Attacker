/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentParser extends HandshakeMessageParser<DtlsHandshakeMessageFragment> {

    private final static Logger LOGGER = LogManager.getLogger();

    public DtlsHandshakeMessageFragmentParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.UNKNOWN, version);
    }

    @Override
    protected void parseHandshakeMessageContent(DtlsHandshakeMessageFragment msg) {
        parseMessageSequence(msg);
        parseFragmentOffset(msg);
        parseFragmentLength(msg);
        msg.setContent(parseByteArrayField(msg.getFragmentLength().getValue()));
    }

    private void parseFragmentOffset(DtlsHandshakeMessageFragment msg) {
        msg.setFragmentOffset(parseIntField(HandshakeByteLength.DTLS_FRAGMENT_OFFSET));
        LOGGER.debug("FragmentOffset:" + msg.getFragmentOffset().getValue());
    }

    private void parseFragmentLength(DtlsHandshakeMessageFragment msg) {
        msg.setFragmentLength(parseIntField(HandshakeByteLength.DTLS_FRAGMENT_LENGTH));
        LOGGER.debug("FragmentLength:" + msg.getFragmentLength().getValue());
    }

    private void parseMessageSequence(DtlsHandshakeMessageFragment msg) {
        msg.setMessageSeq(parseIntField(HandshakeByteLength.DTLS_MESSAGE_SEQUENCE));
        LOGGER.debug("MessageSequence:" + msg.getMessageSeq().getValue());
    }

    @Override
    protected DtlsHandshakeMessageFragment createHandshakeMessage() {
        return new DtlsHandshakeMessageFragment();
    }

}
