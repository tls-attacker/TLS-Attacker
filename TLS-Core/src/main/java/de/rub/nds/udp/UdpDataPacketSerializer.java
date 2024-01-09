/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.udp;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public class UdpDataPacketSerializer extends Serializer<UdpDataPacket> {

    private UdpDataPacket streamContainer;

    public UdpDataPacketSerializer(UdpDataPacket streamContainer) {
        super();
        this.streamContainer = streamContainer;
    }

    @Override
    protected byte[] serializeBytes() {
        return streamContainer.getData().getValue();
    }
}
