/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun;

import de.rub.nds.tlsattacker.core.constants.stun.IpProtocolFamily;

public class IceConfig {

    private String username = "testUser";

    /** 1.2.3.4 */
    private byte[] address = new byte[] { 0x01, 0x02, 0x03, 0x04 };

    private IpProtocolFamily protocolFamily = IpProtocolFamily.IP_V_4;

    private Integer port = 1234;

    private byte[] defaultStunTransactionId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C };

    private Long defaultStunPriority = 0x12345678L;

    public IceConfig() {
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

    public void setAddress(byte[] address) {
        this.address = address;
    }

    public Integer getDefaultPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public IpProtocolFamily getProtocolFamily() {
        return protocolFamily;
    }

    public void setProtocolFamily(IpProtocolFamily protocolFamily) {
        this.protocolFamily = protocolFamily;
    }
}
