/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatMessagePreparator extends ProtocolMessagePreparator<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HeartbeatMessage msg;

    public HeartbeatMessagePreparator(Chooser chooser, HeartbeatMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    private byte[] generatePayload() {
        byte[] payload = new byte[chooser.getConfig().getHeartbeatPayloadLength()];
        chooser.getContext().getRandom().nextBytes(payload);
        return payload;
    }

    private byte[] generatePadding() {
        int paddingLength = chooser.getConfig().getHeartbeatPaddingLength();
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
