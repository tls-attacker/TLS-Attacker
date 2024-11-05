/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.VersionNegotiationPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.VersionNegotiationPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.VersionNegotiationPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.VersionNegotiationPacketSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * The Version Negotiation packet is a response to a client packet that contains a version that is
 * not supported by the server. It is only sent by servers.
 */
@XmlRootElement
public class VersionNegotiationPacket extends LongHeaderPacket {

    private ModifiableByteArray supportedVersions;

    public VersionNegotiationPacket() {
        super(QuicPacketType.VERSION_NEGOTIATION);
    }

    @Override
    public void buildUnprotectedPacketHeader() {}

    @Override
    public void convertCompleteProtectedHeader() {}

    @Override
    public VersionNegotiationPacketHandler getHandler(Context context) {
        return new VersionNegotiationPacketHandler(context.getQuicContext());
    }

    @Override
    public Serializer<VersionNegotiationPacket> getSerializer(Context context) {
        return new VersionNegotiationPacketSerializer(this);
    }

    @Override
    public Preparator<VersionNegotiationPacket> getPreparator(Context context) {
        return new VersionNegotiationPacketPreparator(context.getChooser(), this);
    }

    @Override
    public VersionNegotiationPacketParser getParser(Context context, InputStream stream) {
        return new VersionNegotiationPacketParser(stream, context.getQuicContext());
    }

    public ModifiableByteArray getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(ModifiableByteArray supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public void setSupportedVersions(byte[] supportedVersions) {
        this.supportedVersions =
                ModifiableVariableFactory.safelySetValue(this.supportedVersions, supportedVersions);
    }
}
