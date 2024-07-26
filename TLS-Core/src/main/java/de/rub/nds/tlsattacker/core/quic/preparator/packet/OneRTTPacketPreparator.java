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
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OneRTTPacketPreparator extends QuicPacketPreparator<OneRTTPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public OneRTTPacketPreparator(Chooser chooser, OneRTTPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing 1-RTT Packet");
        calculateApplicationSecrets();
        prepareUnprotectedPacketNumber();
        prepareQuicPacket();
    }

    private void prepareUnprotectedPacketNumber() {
        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getOneRTTPacketPacketNumber());
            context.setOneRTTPacketPacketNumber(context.getOneRTTPacketPacketNumber() + 1);
            LOGGER.debug(
                    "Unprotected Packet Number: {}",
                    packet.getUnprotectedPacketNumber().getValue());
        }
    }

    // TODO: move to handler?
    private void calculateApplicationSecrets() {
        try {
            if (!context.isApplicationSecretsInitialized()) {
                QuicPacketCryptoComputations.calculateApplicationSecrets(context);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | CryptoException e) {
            LOGGER.error("Could not calculate application secrets: {}", e);
        }
    }
}
