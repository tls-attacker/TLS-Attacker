/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatMessagePreparator extends ProtocolMessagePreparator<HeartbeatMessage> {

    private final HeartbeatMessage message;

    public HeartbeatMessagePreparator(TlsContext context, HeartbeatMessage message) {
        super(context, message);
        this.message = message;
    }

    private byte[] generatePayload() {
        int payloadLength = RandomHelper.getRandom().nextInt(context.getConfig().getHeartbeatMaxPayloadLength());
        byte[] payload = new byte[payloadLength];
        RandomHelper.getRandom().nextBytes(payload);
        return payload;
    }

    private byte[] generatePadding() {
        int min = context.getConfig().getHeartbeatMinPaddingLength();
        int max = context.getConfig().getHeartbeatMaxPaddingLength();
        if (max < min) { // TODO perhaps check somewhere different
            throw new ConfigurationException(
                    "Heartbeat minimum padding Length is greater than Heartbeat maxmimum padding length");
        }
        int paddingLength = RandomHelper.getRandom().nextInt(max - min) + min;
        byte[] padding = new byte[paddingLength];
        RandomHelper.getRandom().nextBytes(padding);
        return padding;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setHeartbeatMessageType(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue());
        message.setPayload(generatePayload());
        message.setPayloadLength(message.getPayload().getValue().length);
        message.setPadding(generatePadding());
    }
}
