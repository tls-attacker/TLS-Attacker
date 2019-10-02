/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentSerializer extends HandshakeMessageSerializer<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DtlsHandshakeMessageFragment fragment;

    public DtlsHandshakeMessageFragmentSerializer(DtlsHandshakeMessageFragment message, ProtocolVersion version) {
        super(message, version);
        fragment = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeMessageSequence();
        writeFragmentOffset();
        writeFragmentLength();
        appendBytes(fragment.getContent().getValue());
        return getAlreadySerialized();
    }

    /**
     * Writes the SequenzNumber of the HandshakeMessage into the final byte[]
     */
    private void writeMessageSequence() {
        appendInt(fragment.getMessageSeq().getValue(), HandshakeByteLength.DTLS_MESSAGE_SEQUENCE);
        LOGGER.debug("SequenceNumber: " + fragment.getMessageSeq().getValue());
    }

    /**
     * Writes the FragmentOffset of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentOffset() {
        appendInt(fragment.getFragmentOffset().getValue(), HandshakeByteLength.DTLS_FRAGMENT_OFFSET);
        LOGGER.debug("FragmentOffset: " + fragment.getFragmentOffset().getValue());
    }

    /**
     * Writes the FragmentLength of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentLength() {
        appendInt(fragment.getFragmentLength().getValue(), HandshakeByteLength.DTLS_FRAGMENT_LENGTH);
        LOGGER.debug("FragmentLength: " + fragment.getFragmentLength().getValue());
    }
}
