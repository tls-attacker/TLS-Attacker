/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.udp;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.io.InputStream;

public class UdpDataPacket implements DataContainer<LayerContext> {

    private String sourceIp;

    private String destinationIp;

    private Integer sourcePort;

    private Integer destinationPort;

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

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    @Override
    public String toString() {
        if (sourceIp == null
                || sourcePort == null
                || destinationIp == null
                || destinationPort == null) {
            return "UdpDataPacket";
        }
        return "UdpDataPacket [src: "
                + sourceIp
                + ":"
                + sourcePort
                + ", dst:"
                + destinationIp
                + ":"
                + destinationPort
                + "]";
    }
}
