/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.stun.IpProtocolFamily;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@SuppressWarnings("SpellCheckingInspection")
@XmlRootElement(name = "iceConfig")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(propOrder = {})
public class IceConfig {

    private String username = "testUser";

    /** 1.2.3.4 */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] address = new byte[] { 0x01, 0x02, 0x03, 0x04 };

    private IpProtocolFamily protocolFamily = IpProtocolFamily.IP_V_4;

    private Integer defaultPort = 1234;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultStunTransactionId = new byte[] { 0x21, 0x12, (byte) 0xA4, 0x42, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00 };

    private Long defaultStunPriority = 0x12345678L;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultTieBreaker = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultStunPassword = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    private String defaultRealm = "testRealm";

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultData = new byte[] { 0x01, 0x02, 0x03, 0x04 };

    private Integer defaultErrorCode = 404;

    private String defaultErrorReason = "Not Found :)";

    private String defaultSoftwareString = "Coturn-4.6.1 'Gorst'";

    private Boolean randomizeStunTransactionIds = true;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultTurnDataChannel = new byte[] { 0x45, 0x67};

    private boolean padUdpChannelDataMessages = false;

    public IceConfig() {
    }

    public byte[] getDefaultTurnDataChannel() {
        return defaultTurnDataChannel;
    }

    public void setDefaultTurnDataChannel(byte[] defaultTurnDataChannel) {
        this.defaultTurnDataChannel = defaultTurnDataChannel;
    }

    public boolean isPadUdpChannelDataMessages() {
        return padUdpChannelDataMessages;
    }

    public void setPadUdpChannelDataMessages(boolean padUdpChannelDataMessages) {
        this.padUdpChannelDataMessages = padUdpChannelDataMessages;
    }

    public boolean isRandomizeStunTransactionIds() {
        return randomizeStunTransactionIds;
    }

    public void setRandomizeStunTransactionIds(boolean randomizeStunTransactionIds) {
        this.randomizeStunTransactionIds = randomizeStunTransactionIds;
    }

    public String getDefaultSoftwareString() {
        return defaultSoftwareString;
    }

    public void setDefaultSoftwareString(String defaultSoftwareString) {
        this.defaultSoftwareString = defaultSoftwareString;
    }

    public String getDefaultErrorReason() {
        return defaultErrorReason;
    }

    public void setDefaultErrorReason(String defaultErrorReason) {
        this.defaultErrorReason = defaultErrorReason;
    }

    public void setDefaultErrorCode(Integer defaultErrorCode) {
        this.defaultErrorCode = defaultErrorCode;
    }

    public Integer getDefaultErrorCode() {
        return defaultErrorCode;
    }

    public void setDefaultData(byte[] defaultData) {
        this.defaultData = defaultData;
    }

    public byte[] getDefaultData() {
        return defaultData;
    }

    public String getDefaultRealm() {
        return defaultRealm;
    }

    public void setDefaultRealm(String defaultRealm) {
        this.defaultRealm = defaultRealm;
    }

    public byte[] getDefaultStunPassword() {
        return defaultStunPassword;
    }

    public void setDefaultStunPassword(byte[] defaultStunPassword) {
        this.defaultStunPassword = defaultStunPassword;
    }

    public byte[] getDefaultTieBreaker() {
        return defaultTieBreaker;
    }

    public void setDefaultTieBreaker(byte[] defaultTieBreaker) {
        this.defaultTieBreaker = defaultTieBreaker;
    }

    public Long getDefaultStunPriority() {
        return defaultStunPriority;
    }

    public void setDefaultStunPriority(Long defaultStunPriority) {
        this.defaultStunPriority = defaultStunPriority;
    }

    public byte[] getDefaultStunTransactionId() {
        return defaultStunTransactionId;
    }

    public void setDefaultStunTransactionId(byte[] defaultStunTransactionId) {
        this.defaultStunTransactionId = defaultStunTransactionId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public byte[] getDefaultAddress() {
        return address;
    }

    public void setDefaultAddress(byte[] address) {
        this.address = address;
    }

    public Integer getDefaultPort() {
        return defaultPort;
    }

    public void setDefaultPort(Integer defaultPort) {
        this.defaultPort = defaultPort;
    }

    public IpProtocolFamily getProtocolFamily() {
        return protocolFamily;
    }

    public void setProtocolFamily(IpProtocolFamily protocolFamily) {
        this.protocolFamily = protocolFamily;
    }
}
