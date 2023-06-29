/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionParser
        extends ExtensionParser<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignedCertificateTimestampExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    /**
     * Parses the content of the SingedCertificateTimestampExtension
     *
     * @param msg The Message that should be parsed into
     */
    @Override
    public void parse(SignedCertificateTimestampExtensionMessage msg) {
        msg.setSignedTimestamp(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "The signed certificate timestamp extension parser parsed the value "
                        + bytesToHexString(msg.getSignedTimestamp()));
    }
}
