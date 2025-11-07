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
import de.rub.nds.tlsattacker.core.quic.parser.packet.ZeroRTTPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.ZeroRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.ZeroRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class ZeroRTTPacket extends LongHeaderPacket {

    public ZeroRTTPacket() {
        super(QuicPacketType.ZERO_RTT_PACKET);
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    @Override
    public ZeroRTTPacketHandler getHandler(Context context) {
        return new ZeroRTTPacketHandler(context.getQuicContext());
    }

    @Override
    public ZeroRTTPacketSerializer getSerializer(Context context) {
        return new ZeroRTTPacketSerializer(this);
    }

    @Override
    public ZeroRTTPacketPreparator getPreparator(Context context) {
        return new ZeroRTTPacketPreparator(context.getChooser(), this);
    }

    @Override
    public Parser<ZeroRTTPacket> getParser(Context context, InputStream stream) {
        return new ZeroRTTPacketParser(stream, context.getQuicContext());
    }
}
