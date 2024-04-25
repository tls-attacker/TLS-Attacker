/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.stun.IceChooser;
import java.io.ByteArrayOutputStream;

public class IceContext extends LayerContext {

    private String stunUsername;

    /** Must be 4 bytes long */
    private byte[] address;

    private Integer port;

    private byte[] stunTransactionId;

    private Long stunPriority;

    private byte[] tieBreaker;

    private byte[] messageTranscript;

    private String realm;

    private Integer stunErrorCode;

    public IceContext(Context context) {
        super(context);
    }

    public Integer getStunErrorCode() {
        return stunErrorCode;
    }

    public void setStunErrorCode(Integer stunErrorCode) {
        this.stunErrorCode = stunErrorCode;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public byte[] getMessageTranscript() {
        return messageTranscript;
    }

    public void setMessageTranscript(byte[] messageTranscript) {
        this.messageTranscript = messageTranscript;
    }

    public byte[] getTieBreaker() {
        return tieBreaker;
    }

    public void setTieBreaker(byte[] tieBreaker) {
        this.tieBreaker = tieBreaker;
    }

    public Long getStunPriority() {
        return stunPriority;
    }

    public void setStunPriority(Long stunPriority) {
        this.stunPriority = stunPriority;
    }

    public byte[] getStunTransactionId() {
        return stunTransactionId;
    }

    public void setStunTransactionId(byte[] stunTransactionId) {
        this.stunTransactionId = stunTransactionId;
    }

    public String getStunUsername() {
        return stunUsername;
    }

    public void setStunUsername(String stunUsername) {
        this.stunUsername = stunUsername;
    }

    public byte[] getAddress() {
        return address;
    }

    public void setAddress(byte[] address) {
        this.address = address;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public IceChooser getIceChooser() {
        return new IceChooser(super.getConfig().getIceConfig(), this);
    }
}
