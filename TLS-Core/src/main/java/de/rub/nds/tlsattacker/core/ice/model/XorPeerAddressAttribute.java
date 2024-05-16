/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.model;

import java.io.InputStream;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.XorPeerAddressAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.XorPeerAddressAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.XorPeerAddressAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.XorPeerAddressAttributeSerializer;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

public class XorPeerAddressAttribute extends StunAttribute {

    /** 1 byte */
    private ModifiableByteArray reservedByte;

    /** 1 byte */
    private ModifiableByteArray protocolFamily;

    private ModifiableByteArray xorPeerPort;

    private ModifiableByteArray xorPeerIpAddress;

    /** De-mapped */
    private ModifiableInteger port;

    /** De-mapped */
    private ModifiableByteArray ipAddress;

    public XorPeerAddressAttribute() {
        super(StunAttributeType.XOR_PEER_ADDRESS);
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

    public ModifiableByteArray getXorPeerPort() {
        return xorPeerPort;
    }

    public void setXorPeerPort(ModifiableByteArray xorPeerPort) {
        this.xorPeerPort = xorPeerPort;
    }

    public ModifiableByteArray getXorPeerIpAddress() {
        return xorPeerIpAddress;
    }

    public void setXorPeerIpAddress(ModifiableByteArray xorPeerIpAddress) {
        this.xorPeerIpAddress = xorPeerIpAddress;
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

    public void setXorPeerPort(byte[] xorPeerPort) {
        this.xorPeerPort =
                ModifiableVariableFactory.safelySetValue(this.xorPeerPort, xorPeerPort);
    }

    public void setXorPeerIpAddress(byte[] xorPeerIpAddress) {
        this.xorPeerIpAddress =
                ModifiableVariableFactory.safelySetValue(
                        this.xorPeerIpAddress, xorPeerIpAddress);
    }

    public void setPort(int port) {
        this.port = ModifiableVariableFactory.safelySetValue(this.port, port);
    }

    public void setIpAddress(byte[] ipAddress) {
        this.ipAddress = ModifiableVariableFactory.safelySetValue(this.ipAddress, ipAddress);
    }

    @Override
    public XorPeerAddressAttributeHandler getHandler(IceContext context) {
        return new XorPeerAddressAttributeHandler(context);
    }

    @Override
    public XorPeerAddressAttributeParser getParser(IceContext context, InputStream stream) {
        return new XorPeerAddressAttributeParser(context, stream);
    }

    @Override
    public XorPeerAddressAttributePreparator getPreparator(IceContext context) {
        return new XorPeerAddressAttributePreparator(context.getChooser(), this);
    }

    @Override
    public XorPeerAddressAttributeSerializer getSerializer(IceContext context) {
        return new XorPeerAddressAttributeSerializer(this);
    }
}
