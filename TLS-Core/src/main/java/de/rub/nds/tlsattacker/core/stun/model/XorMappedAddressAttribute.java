/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.XorMappedAddressAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.XorMappedAddressAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.XorMappedAddressAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.XorMappedAddressAttributeSerializer;
import java.io.InputStream;

public class XorMappedAddressAttribute extends StunAttribute {

    /** 1 byte */
    private ModifiableByteArray reservedByte;

    /** 1 byte */
    private ModifiableByteArray protocolFamily;

    private ModifiableByteArray xorMappedPort;

    private ModifiableByteArray xorMappedIpAddress;

    /** De-mapped */
    private ModifiableInteger port;

    /** De-mapped */
    private ModifiableByteArray ipAddress;

    public XorMappedAddressAttribute() {
        super();
    }

    public ModifiableByteArray getReservedByte() {
        return reservedByte;
    }

    public void setReservedByte(ModifiableByteArray reservedByte) {
        this.reservedByte = reservedByte;
    }

    public ModifiableByteArray getProtocolFamily() {
        return protocolFamily;
    }

    public void setProtocolFamily(ModifiableByteArray protocolFamily) {
        this.protocolFamily = protocolFamily;
    }

    public ModifiableByteArray getXorMappedPort() {
        return xorMappedPort;
    }

    public void setXorMappedPort(ModifiableByteArray xorMappedPort) {
        this.xorMappedPort = xorMappedPort;
    }

    public ModifiableByteArray getXorMappedIpAddress() {
        return xorMappedIpAddress;
    }

    public void setXorMappedIpAddress(ModifiableByteArray xorMappedIpAddress) {
        this.xorMappedIpAddress = xorMappedIpAddress;
    }

    public ModifiableInteger getPort() {
        return port;
    }

    public void setPort(ModifiableInteger port) {
        this.port = port;
    }

    public ModifiableByteArray getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(ModifiableByteArray ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setReservedByte(byte[] reservedByte) {
        this.reservedByte =
                ModifiableVariableFactory.safelySetValue(this.reservedByte, reservedByte);
    }

    public void setProtocolFamily(byte[] protocolFamily) {
        this.protocolFamily =
                ModifiableVariableFactory.safelySetValue(this.protocolFamily, protocolFamily);
    }

    public void setXorMappedPort(byte[] xorMappedPort) {
        this.xorMappedPort =
                ModifiableVariableFactory.safelySetValue(this.xorMappedPort, xorMappedPort);
    }

    public void setXorMappedIpAddress(byte[] xorMappedIpAddress) {
        this.xorMappedIpAddress =
                ModifiableVariableFactory.safelySetValue(
                        this.xorMappedIpAddress, xorMappedIpAddress);
    }

    public void setPort(int port) {
        this.port = ModifiableVariableFactory.safelySetValue(this.port, port);
    }

    public void setIpAddress(byte[] ipAddress) {
        this.ipAddress = ModifiableVariableFactory.safelySetValue(this.ipAddress, ipAddress);
    }

    @Override
    public XorMappedAddressAttributeHandler getHandler(IceContext context) {
        return new XorMappedAddressAttributeHandler(context);
    }

    @Override
    public XorMappedAddressAttributeParser getParser(IceContext context, InputStream stream) {
        return new XorMappedAddressAttributeParser(context, stream);
    }

    @Override
    public XorMappedAddressAttributePreparator getPreparator(IceContext context) {
        return new XorMappedAddressAttributePreparator(context.getChooser(), this);
    }

    @Override
    public XorMappedAddressAttributeSerializer getSerializer(IceContext context) {
        return new XorMappedAddressAttributeSerializer(this);
    }
}
