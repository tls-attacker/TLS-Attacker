/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionPreparator
        extends ExtensionPreparator<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RecordSizeLimitExtensionMessage message;

    public RecordSizeLimitExtensionPreparator(
            Chooser chooser, RecordSizeLimitExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        final int recordSizeLimit = chooser.getConfig().getInboundRecordSizeLimit();
        LOGGER.debug("Preparing RecordSizeLimitExtensionMessage with {}", recordSizeLimit);
        message.setRecordSizeLimit(
                DataConverter.intToBytes(
                        recordSizeLimit, ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH));
    }
}
