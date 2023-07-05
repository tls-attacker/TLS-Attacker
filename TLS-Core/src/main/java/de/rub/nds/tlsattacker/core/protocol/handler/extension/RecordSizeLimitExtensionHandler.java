/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.RecordSizeLimit;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionHandler
        extends ExtensionHandler<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordSizeLimitExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(RecordSizeLimitExtensionMessage message) {
        byte[] recordSizeLimitBytes = message.getRecordSizeLimit().getValue();
        if (recordSizeLimitBytes.length != ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH) {
            throw new AdjustmentException("Cannot adjust RecordSizeLimit to a reasonable value");
        }
        Integer recordSizeLimit = ArrayConverter.bytesToInt(recordSizeLimitBytes);
        if (recordSizeLimit < RecordSizeLimit.MIN_RECORD_SIZE_LIMIT) {
            LOGGER.warn(
                    "RecordSizeLimit is smaller than allowed ("
                            + recordSizeLimit
                            + "), resuming anyway");
        }

        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Setting OutboundRecordSizeLimit: " + recordSizeLimit);
            tlsContext.setOutboundRecordSizeLimit(recordSizeLimit);
        }
    }
}
