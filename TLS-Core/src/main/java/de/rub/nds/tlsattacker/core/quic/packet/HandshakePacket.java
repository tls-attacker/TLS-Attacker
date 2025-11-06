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
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
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
        protectedHeaderHelper.write(versionBytes);
    }

    @Override
    public HandshakePacketHandler getHandler(Context context) {
        return new HandshakePacketHandler(context.getQuicContext());
    }

    @Override
    public HandshakePacketSerializer getSerializer(Context context) {
        return new HandshakePacketSerializer(this);
    }

    @Override
    public HandshakePacketPreparator getPreparator(Context context) {
        return new HandshakePacketPreparator(context.getChooser(), this);
    }

    @Override
    public HandshakePacketParser getParser(Context context, InputStream stream) {
        return new HandshakePacketParser(stream, context.getQuicContext());
    }
}
