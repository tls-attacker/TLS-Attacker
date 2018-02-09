/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@SuppressWarnings("serial")
@XmlRootElement
public class SSL2ServerHelloMessage extends SSL2HandshakeMessage {

    @ModifiableVariableProperty
    private ModifiableByte sessionIdHit;

    @ModifiableVariableProperty
    private ModifiableByte certificateType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cipherSuitesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIdLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CERTIFICATE)
    private ModifiableByteArray certificate;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;

    @ModifiableVariableProperty
    private ModifiableByteArray sessionId;

    public SSL2ServerHelloMessage() {
        super(HandshakeMessageType.SSL2_SERVER_HELLO);
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
    }

    public SSL2ServerHelloMessage(Config config) {
        this();
    }

    @Override
    public String toCompactString() {
        return "SSL2 ServerHello Message";
    }

    @Override
    public SSL2ServerHelloHandler getHandler(TlsContext context) {
        return new SSL2ServerHelloHandler(context);
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

    public ModifiableInteger getCipherSuitesLength() {
        return cipherSuitesLength;
    }

    public void setCipherSuitesLength(ModifiableInteger cipherSuitesLength) {
        this.cipherSuitesLength = cipherSuitesLength;
    }

    public void setCipherSuitesLength(int cipherSuitesLength) {
        this.cipherSuitesLength = ModifiableVariableFactory.safelySetValue(this.cipherSuitesLength, cipherSuitesLength);
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
        this.sessionIdLength = sessionIdLength;
    }

    public void setSessionIDLength(int connectionIDLength) {
        this.sessionIdLength = ModifiableVariableFactory.safelySetValue(this.sessionIdLength, connectionIDLength);
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

    public ModifiableByteArray getSessionId() {
        return sessionId;
    }

    public void setSessionId(ModifiableByteArray sessionId) {
        this.sessionId = sessionId;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionId = ModifiableVariableFactory.safelySetValue(this.sessionId, sessionID);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SSL2ServerHelloMessage:");
        sb.append("\n  Protocol Version: ");
        if (getProtocolVersion() != null && getProtocolVersion().getValue() != null) {
            sb.append(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Type: ");
        if (getType() != null && getType().getValue() != null) {
            sb.append(getType().getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Supported CipherSuites: ");
        if (getCipherSuites() != null && getCipherSuites().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getCipherSuites().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  SessionIdHit: ");
        if (getSessionIdHit() != null && getSessionIdHit().getValue() != null) {
            sb.append(getSessionIdHit().getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate: ");
        if (getCertificate() != null && getCertificate().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getCertificate().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  SessionID: ");
        if (getSessionId() != null && getSessionId().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSessionId().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}
