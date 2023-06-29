/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxFragmentLengthExtensionHandler
        extends ExtensionHandler<MaxFragmentLengthExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxFragmentLengthExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(MaxFragmentLengthExtensionMessage message) {
        byte[] maxFragmentLengthBytes = message.getMaxFragmentLength().getValue();
        if (maxFragmentLengthBytes.length != 1) {
            throw new AdjustmentException("Cannot adjust MaxFragmentLength to a reasonable value");
        }
        MaxFragmentLength length =
                MaxFragmentLength.getMaxFragmentLength(maxFragmentLengthBytes[0]);
        if (length == null) {
            LOGGER.warn("Unknown MaxFragmentLength: {}", maxFragmentLengthBytes);
        } else {
            LOGGER.debug("Setting MaxFragmentLength: " + length.getValue());
            tlsContext.setMaxFragmentLength(length);
        }
    }
}
