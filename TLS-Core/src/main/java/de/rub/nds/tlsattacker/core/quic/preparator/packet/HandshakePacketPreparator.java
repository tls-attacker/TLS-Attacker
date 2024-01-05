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
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HandshakePacketPreparator extends LongHeaderPacketPreparator<HandshakePacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HandshakePacketPreparator(Chooser chooser, HandshakePacket packet) {
        super(chooser, packet);
        this.packet = packet;
    }

    @Override
    public void prepare() {
        try {
            if (!context.isHandshakeSecretsInitialized()) {
                QuicPacketCryptoComputations.calculateHandshakeSecrets(context);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | CryptoException e) {
            LOGGER.error(e);
        }
        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getHandshakePacketPacketNumber());
            context.setHandshakePacketPacketNumber(context.getHandshakePacketPacketNumber() + 1);
        }
        prepareLongHeaderPacket();
    }
}
