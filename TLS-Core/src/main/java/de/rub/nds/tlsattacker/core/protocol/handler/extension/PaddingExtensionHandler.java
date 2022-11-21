/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionHandler extends ExtensionHandler<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public PaddingExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new PaddingExtensionParser(pointer, message, config);
    }

    @Override
    public PaddingExtensionPreparator getPreparator(PaddingExtensionMessage message) {
        return new PaddingExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public PaddingExtensionSerializer getSerializer(PaddingExtensionMessage message) {
        return new PaddingExtensionSerializer(message);
    }

    /**
     * Adjusts the TLS context based on the length of the padding extension.
     *
     * @param message
     *                The message for which the context should be adjusted
     */
    @Override
    public void adjustTLSExtensionContext(PaddingExtensionMessage message) {
        context.setPaddingExtensionBytes(message.getPaddingBytes().getValue());
        LOGGER.debug("The context PaddingExtension bytes were set to "
            + ArrayConverter.bytesToHexString(context.getPaddingExtensionBytes()));
    }

}
