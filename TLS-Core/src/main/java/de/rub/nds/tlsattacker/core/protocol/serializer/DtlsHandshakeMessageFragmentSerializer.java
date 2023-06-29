/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentSerializer
        extends HandshakeMessageSerializer<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DtlsHandshakeMessageFragmentSerializer(DtlsHandshakeMessageFragment message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeContent();
        return getAlreadySerialized();
    }

    @Override
    protected byte[] serializeBytes() {
        writeType();
        writeLength();
        writeMessageSequence();
        writeFragmentOffset();
        writeFragmentLength();
        writeContent();
        return getAlreadySerialized();
    }

    private void writeContent() {
        appendBytes(message.getMessageContent().getValue());
        LOGGER.debug("DTLS fragment content: {}", message.getMessageContent().getValue());
    }

    /** Writes the sequenceNumber of the HandshakeMessage into the final byte[] */
    private void writeMessageSequence() {
        appendInt(
                message.getMessageSequence().getValue(), HandshakeByteLength.DTLS_MESSAGE_SEQUENCE);
        LOGGER.debug("SequenceNumber: " + message.getMessageSequence().getValue());
    }

    /** Writes the FragmentOffset of the HandshakeMessage into the final byte[] */
    private void writeFragmentOffset() {
        appendInt(message.getFragmentOffset().getValue(), HandshakeByteLength.DTLS_FRAGMENT_OFFSET);
        LOGGER.debug("FragmentOffset: " + message.getFragmentOffset().getValue());
    }

    /** Writes the FragmentLength of the HandshakeMessage into the final byte[] */
    private void writeFragmentLength() {
        appendInt(message.getFragmentLength().getValue(), HandshakeByteLength.DTLS_FRAGMENT_LENGTH);
        LOGGER.debug("FragmentLength: " + message.getFragmentLength().getValue());
    }
}
