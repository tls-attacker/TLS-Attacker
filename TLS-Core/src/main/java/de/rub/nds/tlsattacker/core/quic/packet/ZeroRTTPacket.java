/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.ZeroRTTPacketHandler;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.ZeroRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.ZeroRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class ZeroRTTPacket extends LongHeaderPacket {

    public ZeroRTTPacket() {
        super(QuicPacketType.ZERO_RTT_PACKET);
        this.setUnprotectedFlags(QuicPacketType.ZERO_RTT_PACKET.getHeader());
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    @Override
    public ZeroRTTPacketHandler getHandler(QuicContext context) {
        return new ZeroRTTPacketHandler(context);
    }

    @Override
    public ZeroRTTPacketSerializer getSerializer(QuicContext context) {
        return new ZeroRTTPacketSerializer(this);
    }

    @Override
    public ZeroRTTPacketPreparator getPreparator(QuicContext context) {
        return new ZeroRTTPacketPreparator(context.getChooser(), this);
    }

    @Override
    public Parser<ZeroRTTPacket> getParser(QuicContext context, InputStream stream) {
        return null;
    }
}
