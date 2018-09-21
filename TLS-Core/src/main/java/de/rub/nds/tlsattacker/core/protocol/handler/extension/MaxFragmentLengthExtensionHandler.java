/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.MaxFragmentLengthExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.MaxFragmentLengthExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.MaxFragmentLengthExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxFragmentLengthExtensionHandler extends ExtensionHandler<MaxFragmentLengthExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxFragmentLengthExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(MaxFragmentLengthExtensionMessage message) {
        byte[] maxFragmentLengthBytes = message.getMaxFragmentLength().getValue();
        if (maxFragmentLengthBytes.length != 1) {
            throw new AdjustmentException("Cannot adjust MaxFragmentLength to a resonable value");
        }
        MaxFragmentLength length = MaxFragmentLength.getMaxFragmentLength(maxFragmentLengthBytes[0]);
        if (length == null) {
            LOGGER.warn("Unknown MaxFragmentLength:" + ArrayConverter.bytesToHexString(maxFragmentLengthBytes));
        } else {
            context.setMaxFragmentLength(length);
        }
    }

    @Override
    public MaxFragmentLengthExtensionParser getParser(byte[] message, int pointer) {
        return new MaxFragmentLengthExtensionParser(pointer, message);
    }

    @Override
    public MaxFragmentLengthExtensionPreparator getPreparator(MaxFragmentLengthExtensionMessage message) {
        return new MaxFragmentLengthExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public MaxFragmentLengthExtensionSerializer getSerializer(MaxFragmentLengthExtensionMessage message) {
        return new MaxFragmentLengthExtensionSerializer(message);
    }

}
