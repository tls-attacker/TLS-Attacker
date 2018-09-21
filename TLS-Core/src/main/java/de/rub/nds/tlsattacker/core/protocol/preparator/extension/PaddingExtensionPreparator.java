/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionPreparator extends ExtensionPreparator<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PaddingExtensionMessage message;

    public PaddingExtensionPreparator(Chooser chooser, PaddingExtensionMessage message,
            PaddingExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.message = message;
    }

    /**
     * Prepares the padding extension padding bytes based on the length set in
     * the context.
     */
    @Override
    public void prepareExtensionContent() {
        message.setPaddingBytes(chooser.getConfig().getDefaultPaddingExtensionBytes());
        LOGGER.debug("Prepared PaddingExtension with "
                + ArrayConverter.bytesToHexString(chooser.getConfig().getDefaultPaddingExtensionBytes())
                + " padding bytes.");
    }

}
