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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.MaxFragmentLengthExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.MaxFragmentLengthExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.MaxFragmentLengthExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxFragmentLengthExtensionHandler extends ExtensionHandler<MaxFragmentLengthExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxFragmentLengthExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(MaxFragmentLengthExtensionMessage message) {
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            byte[] maxFragmentLengthBytes = message.getMaxFragmentLength().getValue();
            if (maxFragmentLengthBytes.length != 1) {
                throw new AdjustmentException("Cannot adjust MaxFragmentLength to a reasonable value");
            }
            MaxFragmentLength length = MaxFragmentLength.getMaxFragmentLength(maxFragmentLengthBytes[0]);
            if (length == null) {
                LOGGER.warn("Unknown MaxFragmentLength:" + ArrayConverter.bytesToHexString(maxFragmentLengthBytes));
            } else {
                LOGGER.debug("Setting MaxFragmentLength: " + length.getValue());
                context.setMaxFragmentLength(length);
            }
        }
    }

    @Override
    public MaxFragmentLengthExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new MaxFragmentLengthExtensionParser(pointer, message, config);
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
