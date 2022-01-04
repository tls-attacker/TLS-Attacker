/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class SSL2ServerVerifyParser extends SSL2HandshakeMessageParser<SSL2ServerVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerVerifyParser(InputStream stream, ProtocolVersion selectedProtocolVersion, TlsContext tlsContext) {
        super(stream, HandshakeMessageType.SSL2_SERVER_VERIFY, selectedProtocolVersion, tlsContext);
    }

    @Override
    protected void parseMessageContent(SSL2ServerVerifyMessage message) {
        LOGGER.debug("Parsing SSL2ServerVerify");
        parseHandshakeMessageContent(message);
    }

    @Override
    protected void parseHandshakeMessageContent(SSL2ServerVerifyMessage msg) {
        parseMessageLength(msg);
        parseEncryptedPart(msg);
    }

    private void parseEncryptedPart(SSL2ServerVerifyMessage message) {
        message.setEncryptedPart(parseByteArrayField(message.getMessageLength().getValue()));
        LOGGER.debug("Encrypted Part: " + ArrayConverter.bytesToHexString(message.getEncryptedPart().getValue()));
    }

}
