/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@SuppressWarnings("serial")
@XmlRootElement(name = "SSL2ServerHello")
public class SSL2ServerHelloMessage extends SSL2Message {

    @ModifiableVariableProperty private ModifiableByte sessionIdHit;

    @ModifiableVariableProperty private ModifiableByte certificateType;

    @ModifiableVariableProperty private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger cipherSuitesLength;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger sessionIdLength;

    @ModifiableVariableProperty private ModifiableByteArray certificate;

    @ModifiableVariableProperty private ModifiableByteArray cipherSuites;

    @ModifiableVariableProperty private ModifiableByteArray sessionId;

    public SSL2ServerHelloMessage() {
        super(SSL2MessageType.SSL_SERVER_HELLO);
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
    }

    @Override
    public String toCompactString() {
        return "SSL2 ServerHello Message";
    }

    @Override
    public SSL2ServerHelloHandler getHandler(Context context) {
        return new SSL2ServerHelloHandler(context.getTlsContext());
    }

    @Override
    public SSL2ServerHelloParser getParser(Context context, InputStream stream) {
        return new SSL2ServerHelloParser(stream, context.getTlsContext());
    }

    @Override
    public SSL2ServerHelloPreparator getPreparator(Context context) {
        return new SSL2ServerHelloPreparator(context.getChooser(), this);
    }

    @Override
    public SSL2ServerHelloSerializer getSerializer(Context context) {
        return new SSL2ServerHelloSerializer(this);
    }

    public ModifiableByte getSessionIdHit() {
        return sessionIdHit;
    }

    public void setSessionIdHit(ModifiableByte sessionIdHit) {
        this.sessionIdHit = sessionIdHit;
    }

    public void setSessionIdHit(byte sessionIdHit) {
        this.sessionIdHit =
                ModifiableVariableFactory.safelySetValue(this.sessionIdHit, sessionIdHit);
    }

    public ModifiableByte getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(ModifiableByte certificateType) {
        this.certificateType = certificateType;
    }

    public void setCertificateType(byte certificateType) {
        this.certificateType =
                ModifiableVariableFactory.safelySetValue(this.certificateType, certificateType);
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setProtocolVersion(byte[] protocolVersion) {
        this.protocolVersion =
                ModifiableVariableFactory.safelySetValue(this.protocolVersion, protocolVersion);
    }

    public ModifiableInteger getCertificateLength() {
        return certificateLength;
    }

    public void setCertificateLength(int certificateLength) {
        this.certificateLength =
                ModifiableVariableFactory.safelySetValue(this.certificateLength, certificateLength);
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
        this.cipherSuitesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.cipherSuitesLength, cipherSuitesLength);
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
        this.sessionIdLength = sessionIdLength;
    }

    public void setSessionIDLength(int connectionIDLength) {
        this.sessionIdLength =
                ModifiableVariableFactory.safelySetValue(this.sessionIdLength, connectionIDLength);
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
        this.cipherSuites =
                ModifiableVariableFactory.safelySetValue(this.cipherSuites, cipherSuites);
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
            sb.append(DataConverter.bytesToHexString(getCipherSuites().getValue()));
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
            sb.append(DataConverter.bytesToHexString(getCertificate().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  SessionID: ");
        if (getSessionId() != null && getSessionId().getValue() != null) {
            sb.append(DataConverter.bytesToHexString(getSessionId().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SSL2_SH";
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 89 * hash + Objects.hashCode(this.sessionIdHit);
        hash = 89 * hash + Objects.hashCode(this.certificateType);
        hash = 89 * hash + Objects.hashCode(this.protocolVersion);
        hash = 89 * hash + Objects.hashCode(this.certificateLength);
        hash = 89 * hash + Objects.hashCode(this.cipherSuitesLength);
        hash = 89 * hash + Objects.hashCode(this.sessionIdLength);
        hash = 89 * hash + Objects.hashCode(this.certificate);
        hash = 89 * hash + Objects.hashCode(this.cipherSuites);
        hash = 89 * hash + Objects.hashCode(this.sessionId);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SSL2ServerHelloMessage other = (SSL2ServerHelloMessage) obj;
        if (!Objects.equals(this.sessionIdHit, other.sessionIdHit)) {
            return false;
        }
        if (!Objects.equals(this.certificateType, other.certificateType)) {
            return false;
        }
        if (!Objects.equals(this.protocolVersion, other.protocolVersion)) {
            return false;
        }
        if (!Objects.equals(this.certificateLength, other.certificateLength)) {
            return false;
        }
        if (!Objects.equals(this.cipherSuitesLength, other.cipherSuitesLength)) {
            return false;
        }
        if (!Objects.equals(this.sessionIdLength, other.sessionIdLength)) {
            return false;
        }
        if (!Objects.equals(this.certificate, other.certificate)) {
            return false;
        }
        if (!Objects.equals(this.cipherSuites, other.cipherSuites)) {
            return false;
        }
        return Objects.equals(this.sessionId, other.sessionId);
    }
}
