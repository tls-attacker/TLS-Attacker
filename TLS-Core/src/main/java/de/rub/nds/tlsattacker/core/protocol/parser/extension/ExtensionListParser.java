/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionListParser extends Parser<List<ExtensionMessage>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;
    private final ProtocolVersion selectedVersion;
    private final boolean helloRetryRequestHint;

    public ExtensionListParser(InputStream stream, TlsContext context, ProtocolVersion selectedVersion,
        boolean helloRetryRequestHint) {
        super(stream);
        this.context = context;
        this.selectedVersion = selectedVersion;
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
            extension.setExtensionBytes(ArrayConverter.concatenate(typeBytes,
                ArrayConverter.intToBytes(length, ExtensionByteLength.EXTENSIONS_LENGTH), extensionPayload));
            Parser parser = extension.getParser(context, new ByteArrayInputStream(extensionPayload));
            if (parser instanceof KeyShareExtensionParser) {
                ((KeyShareExtensionParser) parser).setHelloRetryRequestHint(helloRetryRequestHint);
            }
            parser.parse(extension);
            extensionList.add(extension);
        }
    }

    /**
     * Reads the next bytes as the length of the Extension and writes them in the message
     */
    private int parseExtensionLength() {
        int length = parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH);
        LOGGER.debug("ExtensionLength: {}", length);
        return length;
    }

}
