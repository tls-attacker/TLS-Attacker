/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.tls.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.SSL2ClientHelloHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ServerHelloMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;

    @ModifiableVariableProperty
    private ModifiableByte type;

    @ModifiableVariableProperty
    private ModifiableByte sessionIdHit;

    @ModifiableVariableProperty
    private ModifiableByte certificateType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger ciphersuitesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIDLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CERTIFICATE)
    private ModifiableByteArray certificate;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;

    @ModifiableVariableProperty
    private ModifiableByteArray sessionID;

    public SSL2ServerHelloMessage() {
    }

    public SSL2ServerHelloMessage(TlsConfig config) {
        super();
    }

    @Override
    public String toCompactString() {
        return "SSL2 ServerHello Message";
    }

    @Override
    public SSL2ServerHelloHandler getHandler(TlsContext context) {
        return new SSL2ServerHelloHandler(context);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableByte getType() {
        return type;
    }

    public void setType(ModifiableByte type) {
        this.type = type;
    }

    public void setType(byte type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public ModifiableByte getSessionIdHit() {
        return sessionIdHit;
    }

    public void setSessionIdHit(ModifiableByte sessionIdHit) {
        this.sessionIdHit = sessionIdHit;
    }

    public void setSessionIdHit(byte sessionIdHit) {
        this.sessionIdHit = ModifiableVariableFactory.safelySetValue(this.sessionIdHit, sessionIdHit);
    }

    public ModifiableByte getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(ModifiableByte certificateType) {
        this.certificateType = certificateType;
    }

    public void setCertificateType(byte certificateType) {
        this.certificateType = ModifiableVariableFactory.safelySetValue(this.certificateType, certificateType);
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setProtocolVersion(byte[] protocolVersion) {
        this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, protocolVersion);
    }

    public ModifiableInteger getCertificateLength() {
        return certificateLength;
    }

    public void setCertificateLength(int certificateLength) {
        this.certificateLength = ModifiableVariableFactory.safelySetValue(this.certificateLength, certificateLength);
    }

    public void setCertificateLength(ModifiableInteger certificateLength) {
        this.certificateLength = certificateLength;
    }

    public ModifiableInteger getCiphersuitesLength() {
        return ciphersuitesLength;
    }

    public void setCiphersuitesLength(ModifiableInteger ciphersuitesLength) {
        this.ciphersuitesLength = ciphersuitesLength;
    }

    public void setCiphersuitesLength(int ciphersuitesLength) {
        this.ciphersuitesLength = ModifiableVariableFactory.safelySetValue(this.ciphersuitesLength, ciphersuitesLength);
    }

    public ModifiableInteger getSessionIDLength() {
        return sessionIDLength;
    }

    public void setSessionIDLength(ModifiableInteger sessionIDLength) {
        this.sessionIDLength = sessionIDLength;
    }

    public void setSessionIDLength(int connectionIDLength) {
        this.sessionIDLength = ModifiableVariableFactory.safelySetValue(this.sessionIDLength, connectionIDLength);
    }

    public ModifiableByteArray getCertificate() {
        return certificate;
    }

    public void setCertificate(ModifiableByteArray certificate) {
        this.certificate = certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = ModifiableVariableFactory.safelySetValue(this.certificate, certificate);
    }

    public ModifiableByteArray getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(ModifiableByteArray cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setCipherSuites(byte[] cipherSuites) {
        this.cipherSuites = ModifiableVariableFactory.safelySetValue(this.cipherSuites, cipherSuites);
    }

    public ModifiableByteArray getSessionID() {
        return sessionID;
    }

    public void setSessionID(ModifiableByteArray sessionID) {
        this.sessionID = sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = ModifiableVariableFactory.safelySetValue(this.sessionID, sessionID);
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        //TODO
        return sb.toString();
    }
}
