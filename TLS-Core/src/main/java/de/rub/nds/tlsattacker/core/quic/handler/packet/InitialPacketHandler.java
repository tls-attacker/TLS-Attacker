/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InitialPacketHandler extends LongHeaderPacketHandler<InitialPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public InitialPacketHandler(QuicContext quicContext) {
        super(quicContext);
    }

    @Override
    public void adjustContext(InitialPacket packet) {
        // update quic context
        if (!quicContext.getConfig().isEchoQuic()) {
            quicContext.setDestinationConnectionId(packet.getSourceConnectionId().getValue());
        }

        // update quic keys
        try {
            if (!quicContext.isInitialSecretsInitialized()) {
                QuicPacketCryptoComputations.calculateInitialSecrets(quicContext);
            }
        } catch (NoSuchAlgorithmException | CryptoException e) {
            LOGGER.error("Could not calculate initial secrets", e);
        }
    }
}
