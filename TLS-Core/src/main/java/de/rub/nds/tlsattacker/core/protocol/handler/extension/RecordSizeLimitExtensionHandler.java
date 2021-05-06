/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import static de.rub.nds.tlsattacker.core.constants.RecordSizeLimit.MIN_RECORD_SIZE_LIMIT;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RecordSizeLimitExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RecordSizeLimitExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionHandler extends ExtensionHandler<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordSizeLimitExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(RecordSizeLimitExtensionMessage message) {
        byte[] recordSizeLimitBytes = message.getRecordSizeLimit().getValue();
        if (recordSizeLimitBytes.length != ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH) {
            throw new AdjustmentException("Cannot adjust RecordSizeLimit to a reasonable value");
        }
        Integer recordSizeLimit = ArrayConverter.bytesToInt(recordSizeLimitBytes);
        // TODO: RFC8449 says 'An endpoint MUST treat receipt of a smaller value as a fatal error and generate an
        // "illegal_parameter" alert.'. We might want to think about any interesting cases that could come up with
        // "invalid" values here. What happens if this is <= 5 so that only the record header fits?
        if (recordSizeLimit < MIN_RECORD_SIZE_LIMIT) {
            LOGGER.warn("RecordSizeLimit is smaller than allowed: " + recordSizeLimit);
            // return;
        }

        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            LOGGER.debug("Setting ClientRecordSizeLimit: " + recordSizeLimit);
            context.setClientRecordSizeLimit(recordSizeLimit);
        } else {
            LOGGER.debug("Setting ServerRecordSizeLimit: " + recordSizeLimit);
            context.setServerRecordSizeLimit(recordSizeLimit);
        }
        // on receival of a record_size_limit extension, we answer with one ourselves
        context.getConfig().setAddRecordSizeLimitExtension(Boolean.TRUE);
    }

    @Override
    public RecordSizeLimitExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new RecordSizeLimitExtensionParser(pointer, message, config);
    }

    @Override
    public RecordSizeLimitExtensionPreparator getPreparator(RecordSizeLimitExtensionMessage message) {
        return new RecordSizeLimitExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public RecordSizeLimitExtensionSerializer getSerializer(RecordSizeLimitExtensionMessage message) {
        return new RecordSizeLimitExtensionSerializer(message);
    }
}
