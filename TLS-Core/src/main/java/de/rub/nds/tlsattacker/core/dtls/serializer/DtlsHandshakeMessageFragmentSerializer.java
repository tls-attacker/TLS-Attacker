/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.dtls.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentSerializer
        extends Serializer<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DtlsHandshakeMessageFragment fragment;

    public DtlsHandshakeMessageFragmentSerializer(DtlsHandshakeMessageFragment fragment) {
        super();
        this.fragment = fragment;
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

    /** Writes the Type of the HandshakeMessage into the final byte[] */
    protected void writeType() {
        appendByte(fragment.getType().getValue());
        LOGGER.debug("Type: {}", fragment.getType().getValue());
    }

    /** Writes the message length of the HandshakeMessage into the final byte[] */
    protected void writeLength() {
        appendInt(fragment.getLength().getValue(), HandshakeByteLength.MESSAGE_LENGTH_FIELD);
        LOGGER.debug("Length: {}", fragment.getLength().getValue());
    }

    private void writeContent() {
        appendBytes(fragment.getFragmentContent().getValue());
        LOGGER.debug("DTLS fragment content: {}", fragment.getFragmentContent().getValue());
    }

    /** Writes the sequenceNumber of the HandshakeMessage into the final byte[] */
    private void writeMessageSequence() {
        appendInt(
                fragment.getMessageSequence().getValue(),
                HandshakeByteLength.DTLS_MESSAGE_SEQUENCE);
        LOGGER.debug("SequenceNumber: {}", fragment.getMessageSequence().getValue());
    }

    /** Writes the FragmentOffset of the HandshakeMessage into the final byte[] */
    private void writeFragmentOffset() {
        appendInt(
                fragment.getFragmentOffset().getValue(), HandshakeByteLength.DTLS_FRAGMENT_OFFSET);
        LOGGER.debug("FragmentOffset: {}", fragment.getFragmentOffset().getValue());
    }

    /** Writes the FragmentLength of the HandshakeMessage into the final byte[] */
    private void writeFragmentLength() {
        appendInt(
                fragment.getFragmentLength().getValue(), HandshakeByteLength.DTLS_FRAGMENT_LENGTH);
        LOGGER.debug("FragmentLength: {}", fragment.getFragmentLength().getValue());
    }
}
