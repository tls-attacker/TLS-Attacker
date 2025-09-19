/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetryPacketPreparator extends LongHeaderPacketPreparator<RetryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetryPacketPreparator(Chooser chooser, RetryPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Retry Packet");
        prepareUnprotectedFlags();
        prepareRetryToken();
        packet.setUnprotectedPacketNumber(0); // Retry packets do not have a packet number
        packet.setUnprotectedPayload(new byte[0]);
        prepareLongHeaderPacket();
        prepareRetryIntegrityTag();
    }

    private void prepareRetryToken() {
        packet.setRetryToken(context.getConfig().getDefaultQuicServerRetryToken());
        LOGGER.debug("Token: {}", packet.getRetryToken().getValue());
    }

    private void prepareUnprotectedFlags() {
        packet.setUnprotectedFlags(QuicPacketType.RETRY_PACKET.getHeader(context.getQuicVersion()));
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }

    private void prepareRetryIntegrityTag() {
        byte[] tag = QuicPacketCryptoComputations.calculateRetryIntegrityTag(context, packet);
        packet.setRetryIntegrityTag(tag);
    }
}
