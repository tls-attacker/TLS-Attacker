/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerVerifyParser extends SSL2MessageParser<SSL2ServerVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerVerifyParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SSL2ServerVerifyMessage msg) {
        LOGGER.debug("Parsing SSL2ServerVerify");
        parseEncryptedPart(msg);
    }

    private void parseEncryptedPart(SSL2ServerVerifyMessage message) {
        message.setEncryptedPart(parseByteArrayField(message.getMessageLength().getValue()));
        LOGGER.debug("Encrypted Part: {}", message.getEncryptedPart().getValue());
    }
}
