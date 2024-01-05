/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionParser
        extends ExtensionParser<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordSizeLimitExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(RecordSizeLimitExtensionMessage message) {
        LOGGER.debug("Parsing RecordSizeLimitExtensionMessage");
        parseRecordSizeLimit(message);
    }

    private void parseRecordSizeLimit(RecordSizeLimitExtensionMessage message) {
        message.setRecordSizeLimit(
                parseByteArrayField(ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH));
        LOGGER.debug("RecordSizeLimit: {}", message.getRecordSizeLimit().getValue());
    }
}
