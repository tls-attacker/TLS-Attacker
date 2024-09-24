/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionNegotiationPacketHandler
        extends LongHeaderPacketHandler<VersionNegotiationPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionNegotiationPacketHandler(QuicContext quicContext) {
        super(quicContext);
    }

    @Override
    public void adjustContext(VersionNegotiationPacket packet) {
        adjustSupportedVersions(packet);
    }

    private void adjustSupportedVersions(VersionNegotiationPacket packet) {
        List<byte[]> versionList = convertVersions(packet.getSupportedVersions().getValue());
        quicContext.setSupportedVersions(versionList);
        if (versionList != null) {
            LOGGER.debug("Set ServerSupportedQuicVersions in Context to {}", versionList);
        } else {
            LOGGER.debug("Set ClientSupportedCipherSuites in Context to null");
        }
    }

    private List<byte[]> convertVersions(byte[] bytesToConvert) {
        if (bytesToConvert.length % 8 != 0) {
            LOGGER.warn("Cannot convert: {} to a List<byte[]>", bytesToConvert);
            return null;
        }

        List<byte[]> list = new LinkedList<>();
        for (int i = 0; i < bytesToConvert.length; i += 8) {
            byte[] chunk = new byte[8];
            System.arraycopy(bytesToConvert, i, chunk, 0, 8);
            list.add(chunk);
        }
        return list;
    }
}
