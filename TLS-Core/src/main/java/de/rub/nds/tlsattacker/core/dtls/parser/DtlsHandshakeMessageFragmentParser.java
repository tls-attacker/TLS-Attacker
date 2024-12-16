/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.dtls.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentParser extends Parser<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    private TlsContext context;

    public DtlsHandshakeMessageFragmentParser(InputStream stream, TlsContext context) {
        super(stream);
        this.context = context;
    }

    @Override
    public void parse(DtlsHandshakeMessageFragment msg) {
        parseType(msg);
        parseLength(msg);
        parseMessageSequence(msg);
        parseFragmentOffset(msg);
        parseFragmentLength(msg);
        msg.setFragmentContent(parseByteArrayField(msg.getFragmentLength().getValue()));
    }

    private void parseType(DtlsHandshakeMessageFragment msg) {
        msg.setType(parseByteField(HandshakeByteLength.MESSAGE_TYPE));
        LOGGER.debug("Type:" + msg.getType().getValue());
    }

    private void parseLength(DtlsHandshakeMessageFragment msg) {
        msg.setLength(parseIntField(HandshakeByteLength.MESSAGE_LENGTH_FIELD));
        LOGGER.debug("Length:" + msg.getLength().getValue());
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
        msg.setMessageSequence(parseIntField(HandshakeByteLength.DTLS_MESSAGE_SEQUENCE));
        LOGGER.debug("MessageSequence:" + msg.getMessageSequence().getValue());
    }
}
