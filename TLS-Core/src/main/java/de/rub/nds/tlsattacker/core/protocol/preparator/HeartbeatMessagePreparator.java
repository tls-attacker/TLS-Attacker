/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessagePreparator extends TlsMessagePreparator<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HeartbeatMessage msg;

    public HeartbeatMessagePreparator(Chooser chooser, HeartbeatMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    private byte[] generatePayload() {
        int payloadLength = chooser.getConfig().getHeartbeatPayloadLength();
        if (payloadLength < 0) {
            LOGGER.warn("HeartBeat payload length is smaller than 0. Setting it to 0 instead");
            payloadLength = 0;
        } else if (payloadLength > 65536) {
            LOGGER.warn("HeartBeat payload length is bigger than the max value. Setting it to max value.");
            payloadLength = 65536;
        }
        byte[] payload = new byte[payloadLength];
        chooser.getContext().getRandom().nextBytes(payload);
        return payload;
    }

    private byte[] generatePadding() {
        int paddingLength = chooser.getConfig().getHeartbeatPaddingLength();
        if (paddingLength < 0) {
            LOGGER.warn("HeartBeat padding length is smaller than 0. Setting it to 0 instead");
            paddingLength = 0;
        } else if (paddingLength > 65536) {
            LOGGER.warn("HeartBeat padding length is bigger than the max value. Setting it to max value.");
            paddingLength = 65536;
        }
        byte[] padding = new byte[paddingLength];
        chooser.getContext().getRandom().nextBytes(padding);
        return padding;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing HeartbeatMessage");
        // TODO currently only requests supported
        prepareHeartbeatMessageType(msg);
        preparePayload(msg);
        preparePayloadLength(msg);
        preparePadding(msg);
    }

    private void prepareHeartbeatMessageType(HeartbeatMessage msg) {
        msg.setHeartbeatMessageType(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue());
        LOGGER.debug("HeartbeatMessageType: " + msg.getHeartbeatMessageType().getValue());
    }

    private void preparePayload(HeartbeatMessage msg) {
        msg.setPayload(generatePayload());
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
    }

    private void preparePayloadLength(HeartbeatMessage msg) {
        msg.setPayloadLength(msg.getPayload().getValue().length);
        LOGGER.debug("PayloadLength: " + msg.getPayloadLength().getValue());
    }

    private void preparePadding(HeartbeatMessage msg) {
        msg.setPadding(generatePadding());
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getPadding().getValue()));
    }
}
