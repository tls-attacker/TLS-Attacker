/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionListParser extends Parser<List<ExtensionMessage>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;
    private final boolean helloRetryRequestHint;

    public ExtensionListParser(
            InputStream stream, TlsContext tlsContext, boolean helloRetryRequestHint) {
        super(stream);
        this.tlsContext = tlsContext;
        this.helloRetryRequestHint = helloRetryRequestHint;
    }

    @Override
    public void parse(List<ExtensionMessage> extensionList) {
        while (getBytesLeft() > 0) {
            byte[] typeBytes = parseByteArrayField(ExtensionByteLength.TYPE);
            ExtensionType extensionType = ExtensionType.getExtensionType(typeBytes);
            LOGGER.debug("ExtensionType: {} ({})", typeBytes, extensionType);
            int length = parseExtensionLength();
            byte[] extensionPayload = parseByteArrayField(length);
            ExtensionMessage extension = ExtensionFactory.getExtension(extensionType);
            extension.setExtensionType(typeBytes);
            extension.setExtensionLength(length);
            extension.setExtensionContent(extensionPayload);
            extension.setExtensionBytes(
                    ArrayConverter.concatenate(
                            typeBytes,
                            ArrayConverter.intToBytes(
                                    length, ExtensionByteLength.EXTENSIONS_LENGTH),
                            extensionPayload));
            Parser parser =
                    extension.getParser(tlsContext, new ByteArrayInputStream(extensionPayload));
            if (parser instanceof KeyShareExtensionParser) {
                ((KeyShareExtensionParser) parser).setHelloRetryRequestHint(helloRetryRequestHint);
            }
            parser.parse(extension);
            extensionList.add(extension);
        }
    }

    /** Reads the next bytes as the length of the Extension and writes them in the message */
    private int parseExtensionLength() {
        int length = parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH);
        LOGGER.debug("ExtensionLength: {}", length);
        return length;
    }
}
