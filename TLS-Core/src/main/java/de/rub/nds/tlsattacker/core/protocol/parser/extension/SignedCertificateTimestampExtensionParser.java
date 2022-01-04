/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

public class SignedCertificateTimestampExtensionParser
        extends ExtensionParser<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignedCertificateTimestampExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    /**
     * Parses the content of the SingedCertificateTimestampExtension
     *
     * @param msg
     *            The Message that should be parsed into
     */
    @Override
    public void parseExtensionMessageContent(SignedCertificateTimestampExtensionMessage msg) {
        msg.setSignedTimestamp(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("The signed certificate timestamp extension parser parsed the value "
                + bytesToHexString(msg.getSignedTimestamp()));
    }
}
