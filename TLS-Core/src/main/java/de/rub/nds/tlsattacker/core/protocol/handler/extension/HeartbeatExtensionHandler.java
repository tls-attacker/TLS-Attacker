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
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HeartbeatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.HeartbeatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HeartbeatExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatExtensionHandler extends ExtensionHandler<HeartbeatExtensionMessage> {

    public HeartbeatExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSContext(HeartbeatExtensionMessage message) {
        byte[] heartbeatMode = message.getHeartbeatMode().getValue();
        if (heartbeatMode.length != 1) {
            throw new AdjustmentException("Cannot set Heartbeatmode to a resonable Value");
        }
        HeartbeatMode mode = HeartbeatMode.getHeartbeatMessageType(heartbeatMode[0]);
        if (mode == null) {
            LOGGER.warn("Unknown HeartbeatMode: " + ArrayConverter.bytesToHexString(heartbeatMode));
        } else {
            context.setHeartbeatMode(mode);
        }
    }

    @Override
    public HeartbeatExtensionParser getParser(byte[] message, int pointer) {
        return new HeartbeatExtensionParser(pointer, message);
    }

    @Override
    public HeartbeatExtensionPreparator getPreparator(HeartbeatExtensionMessage message) {
        return new HeartbeatExtensionPreparator(context, message, getSerializer(message));
    }

    @Override
    public HeartbeatExtensionSerializer getSerializer(HeartbeatExtensionMessage message) {
        return new HeartbeatExtensionSerializer(message);
    }
}
