/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.HandshakePacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.HandshakePacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.HandshakePacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.HandshakePacketSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class HandshakePacket extends LongHeaderPacket {

    private static final Logger LOGGER = LogManager.getLogger();

    public HandshakePacket() {
        super(QuicPacketType.HANDSHAKE_PACKET);
        this.packetSecret = QuicCryptoSecrets.HANDSHAKE_SECRET;
    }

    public HandshakePacket(byte flags, byte[] versionBytes) {
        super(QuicPacketType.HANDSHAKE_PACKET);
        setProtectedFlags(flags);
        protectedHeaderHelper.write(flags);
        this.packetSecret = QuicCryptoSecrets.HANDSHAKE_SECRET;
        setQuicVersion(versionBytes);
        try {
            protectedHeaderHelper.write(versionBytes);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    @Override
    public HandshakePacketHandler getHandler(QuicContext context) {
        return null;
    }

    @Override
    public HandshakePacketSerializer getSerializer(QuicContext context) {
        return new HandshakePacketSerializer(this);
    }

    @Override
    public HandshakePacketPreparator getPreparator(QuicContext context) {
        return new HandshakePacketPreparator(context.getChooser(), this);
    }

    @Override
    public HandshakePacketParser getParser(QuicContext context, InputStream stream) {
        return new HandshakePacketParser(stream, context);
    }
}
