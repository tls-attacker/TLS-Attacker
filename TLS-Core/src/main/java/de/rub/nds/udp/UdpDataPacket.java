/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.udp;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.io.InputStream;

public class UdpDataPacket implements DataContainer<LayerContext> {

    private transient byte[] configData;

    private ModifiableByteArray data;

    public UdpDataPacket() {}

    public UdpDataPacket(byte[] configData) {
        this.configData = configData;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public UdpDataPacketParser getParser(LayerContext context, InputStream stream) {
        return new UdpDataPacketParser(stream);
    }

    @Override
    public UdpDataPacketPreparator getPreparator(LayerContext context) {
        return new UdpDataPacketPreparator(context.getChooser(), this);
    }

    @Override
    public UdpDataPacketSerializer getSerializer(LayerContext context) {
        return new UdpDataPacketSerializer(this);
    }

    @Override
    public UdpDataPacketHandler getHandler(LayerContext context) {
        return new UdpDataPacketHandler();
    }

    public byte[] getConfigData() {
        return configData;
    }

    public void setConfigData(byte[] configData) {
        this.configData = configData;
    }
}
