/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentSerializer extends HandshakeMessageSerializer<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DtlsHandshakeMessageFragmentSerializer(DtlsHandshakeMessageFragment message, ProtocolVersion version) {
        super(message, version);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeMessageSequence();
        writeFragmentOffset();
        writeFragmentLength();
        appendBytes(message.getContent().getValue());
        return getAlreadySerialized();
    }

    /**
     * Writes the sequenceNumber of the HandshakeMessage into the final byte[]
     */
    private void writeMessageSequence() {
        appendInt(message.getMessageSeq().getValue(), HandshakeByteLength.DTLS_MESSAGE_SEQUENCE);
        LOGGER.debug("SequenceNumber: " + message.getMessageSeq().getValue());
    }

    /**
     * Writes the FragmentOffset of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentOffset() {
        appendInt(message.getFragmentOffset().getValue(), HandshakeByteLength.DTLS_FRAGMENT_OFFSET);
        LOGGER.debug("FragmentOffset: " + message.getFragmentOffset().getValue());
    }

    /**
     * Writes the FragmentLength of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentLength() {
        appendInt(message.getFragmentLength().getValue(), HandshakeByteLength.DTLS_FRAGMENT_LENGTH);
        LOGGER.debug("FragmentLength: " + message.getFragmentLength().getValue());
    }
}
