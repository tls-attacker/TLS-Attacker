/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InitialPacketPreparator extends LongHeaderPacketPreparator<InitialPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public InitialPacketPreparator(Chooser chooser, InitialPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Inital Packet");
        prepareUnprotectedFlags();
        calculateInitialSecrets();
        prepareUnprotectedPacketNumber();
        prepareToken();
        prepareLongHeaderPacket();
    }

    private void prepareToken() {
        if (context.getInitialPacketToken() != null) {
            packet.setToken(context.getInitialPacketToken());
            packet.setTokenLength(context.getInitialPacketToken().length);
        } else {
            packet.setToken(new byte[] {});
            packet.setTokenLength(0);
        }
        LOGGER.debug("Token: {}", packet.getToken().getValue());
        LOGGER.debug("Token Length: {}", packet.getTokenLength());
    }

    private void prepareUnprotectedPacketNumber() {
        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getInitialPacketPacketNumber());
            context.setInitialPacketPacketNumber(context.getInitialPacketPacketNumber() + 1);
            LOGGER.debug(
                    "Unprotected Packet Number: {}",
                    packet.getUnprotectedPacketNumber().getValue());
        }
    }

    // TODO: move to handler?
    private void calculateInitialSecrets() {
        try {
            if (!context.isInitialSecretsInitialized()) {
                QuicPacketCryptoComputations.calculateInitialSecrets(context);
            }
        } catch (NoSuchAlgorithmException | CryptoException e) {
            LOGGER.error("Could not calculate initial secrets: {}", e);
        }
    }

    private void prepareUnprotectedFlags() {
        packet.setUnprotectedFlags(
                QuicPacketType.INITIAL_PACKET.getHeader(context.getQuicVersion()));
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }

    @Override
    protected int calculatePadding() {
        return Math.max(
                0,
                MiscRfcConstants.SMALLEST_MAX_DATAGRAM_SIZE
                        - (QuicPacketByteLength.QUIC_FIRST_HEADER_BYTE
                                + QuicPacketByteLength.QUIC_VERSION_LENGTH
                                + QuicPacketByteLength.DESTINATION_CONNECTION_ID_LENGTH
                                + context.getDestinationConnectionId().length
                                + QuicPacketByteLength.SOURCE_CONNECTION_ID_LENGTH
                                + context.getSourceConnectionId().length
                                + (packet.getToken().getValue().length == 0
                                        ? QuicPacketByteLength.NO_TOKEN_TOKEN_LENGTH
                                        : packet.getTokenLength().getValue()
                                                + packet.getTokenLengthSize())
                                + 2 // length of "Length" field if packet is 1200 bytes
                                + packet.getPacketNumberLength().getValue()
                                + packet.getUnprotectedPayload().getValue().length
                                + MiscRfcConstants.AUTH_TAG_LENGTH));
    }
}
