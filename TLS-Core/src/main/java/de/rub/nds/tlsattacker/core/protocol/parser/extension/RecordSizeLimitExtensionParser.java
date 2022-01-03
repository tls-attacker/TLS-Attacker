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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionParser extends ExtensionParser<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordSizeLimitExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(RecordSizeLimitExtensionMessage message) {
        LOGGER.debug("Parsing RecordSizeLimitExtensionMessage");
        parseRecordSizeLimit(message);
    }

    @Override
    protected RecordSizeLimitExtensionMessage createExtensionMessage() {
        return new RecordSizeLimitExtensionMessage();
    }

    private void parseRecordSizeLimit(RecordSizeLimitExtensionMessage message) {
        message.setRecordSizeLimit(parseByteArrayField(ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH));
        LOGGER.debug("RecordSizeLimit: " + ArrayConverter.bytesToHexString(message.getRecordSizeLimit().getValue()));
    }
}
