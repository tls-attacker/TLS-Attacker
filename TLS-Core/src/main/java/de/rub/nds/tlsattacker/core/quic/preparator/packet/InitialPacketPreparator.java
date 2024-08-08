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
        this.packet = packet;
    }

    @Override
    public void prepare() {
        packet.setUnprotectedFlags(
                QuicPacketType.INITIAL_PACKET.getHeader(context.getQuicVersion()));
        if (!context.isInitialSecretsInitialized()) {
            try {
                QuicPacketCryptoComputations.calculateInitialSecrets(context);
            } catch (NoSuchAlgorithmException | CryptoException e) {
                LOGGER.error("Could not calculate initial secrets: ", e);
                return;
            }
        }

        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getInitialPacketPacketNumber());
            context.setInitialPacketPacketNumber(context.getInitialPacketPacketNumber() + 1);
        }

        if (context.getInitialPacketToken() != null) {
            packet.setToken(context.getInitialPacketToken());
            packet.setTokenLength(context.getInitialPacketToken().length);
        } else {
            packet.setToken(new byte[] {});
            packet.setTokenLength(0);
        }

        prepareLongHeaderPacket();
    }

    @Override
    protected int calculatePadding() {
        //        Initial Packet {
        //            Header Form (1) = 1,
        //            Fixed Bit (1) = 1,
        //            Long Packet Type (2) = 0,
        //            Reserved Bits (2),
        //            Packet Number Length (2),
        //            Version (32),
        //            Destination Connection ID Length (8),
        //            Destination Connection ID (0..160),
        //            Source Connection ID Length (8),
        //            Source Connection ID (0..160),
        //            Token Length (i),
        //            Token (..),
        //            Length (i),
        //            Packet Number (8..32),
        //            Packet Payload (8..),
        //        }
        // 1200 - ( (HeaderForm + Fixed Bit + Long Packet Type + Reserved Bits + Packet Number
        // Length) + Version + DestConIdLen + DestConId + SrcConIdLen + SrcConId + TokenLen +
        // PacketLen + Payload(= data + AuthTag)
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
