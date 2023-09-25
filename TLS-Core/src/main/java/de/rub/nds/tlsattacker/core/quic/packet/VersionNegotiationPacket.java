/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.VersionNegotiationPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.VersionNegotiationPacketParser;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The Version Negotiation packet is a response to a client packet that contains a version that is
 * not supported by the server. It is only sent by servers.
 */
@XmlRootElement
public class VersionNegotiationPacket extends LongHeaderPacket<VersionNegotiationPacket> {

    private List<byte[]> supportedVersions;

    public VersionNegotiationPacket() {
        super(QuicPacketType.VERSION_NEGOTIATION);
        this.supportedVersions = new ArrayList<>();
    }

    @Override
    public void buildUnprotectedPacketHeader() {}

    @Override
    public void convertCompleteProtectedHeader() {}

    @Override
    public VersionNegotiationPacketHandler getHandler(QuicContext context) {
        return new VersionNegotiationPacketHandler(context);
    }

    @Override
    public Serializer<VersionNegotiationPacket> getSerializer(QuicContext context) {
        return null;
    }

    @Override
    public Preparator<VersionNegotiationPacket> getPreparator(QuicContext context) {
        return null;
    }

    @Override
    public VersionNegotiationPacketParser getParser(QuicContext context, InputStream stream) {
        return new VersionNegotiationPacketParser(stream, context);
    }

    public void addSupportedVersion(byte[] version) {
        this.supportedVersions.add(version);
    }

    public List<byte[]> getSupportedVersions() {
        return supportedVersions;
    }
}
