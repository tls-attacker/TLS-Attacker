/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.HeartbeatExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.HeartbeatExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.HeartbeatExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        return new HeartbeatExtensionPreparator(context, message);
    }

    @Override
    public HeartbeatExtensionSerializer getSerializer(HeartbeatExtensionMessage message) {
        return new HeartbeatExtensionSerializer(message);
    }
}
