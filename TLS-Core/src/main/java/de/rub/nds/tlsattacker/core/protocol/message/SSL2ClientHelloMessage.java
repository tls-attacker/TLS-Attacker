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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ClientHelloHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@SuppressWarnings("serial")
@XmlRootElement
public class SSL2ClientHelloMessage extends SSL2HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cipherSuiteLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIdLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger challengeLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;

    private ModifiableByteArray sessionId;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray challenge;

    public SSL2ClientHelloMessage() {
        super(HandshakeMessageType.SSL2_CLIENT_HELLO);
    }

    public SSL2ClientHelloMessage(Config config) {
        this();
    }

    @Override
    public String toCompactString() {
        return "SSL2 ClientHello Message";
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

    public ModifiableInteger getCipherSuiteLength() {
        return cipherSuiteLength;
    }

    public void setCipherSuiteLength(ModifiableInteger cipherSuiteLength) {
        this.cipherSuiteLength = cipherSuiteLength;
    }

    public void setCipherSuiteLength(int cipherSuiteLength) {
        this.cipherSuiteLength = ModifiableVariableFactory.safelySetValue(this.cipherSuiteLength, cipherSuiteLength);
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

    public ModifiableByteArray getChallenge() {
        return challenge;
    }

    public void setChallenge(ModifiableByteArray challenge) {
        this.challenge = challenge;
    }

    public void setChallenge(byte[] challenge) {
        this.challenge = ModifiableVariableFactory.safelySetValue(this.challenge, challenge);
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
        this.sessionIdLength = sessionIdLength;
    }

    public void setSessionIDLength(int sessionIDLength) {
        this.sessionIdLength = ModifiableVariableFactory.safelySetValue(this.sessionIdLength, sessionIDLength);
    }

    public ModifiableInteger getChallengeLength() {
        return challengeLength;
    }

    public void setChallengeLength(int challengeLength) {
        this.challengeLength = ModifiableVariableFactory.safelySetValue(this.challengeLength, challengeLength);
    }

    public void setChallengeLength(ModifiableInteger challengeLength) {
        this.challengeLength = challengeLength;
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
        sb.append("SSL2ClientHelloMessage:");
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
        sb.append("\n  Challange: ");
        if (getChallenge() != null && getChallenge().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getChallenge().getValue()));
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

    @Override
    public SSL2ClientHelloHandler getHandler(TlsContext context) {
        return new SSL2ClientHelloHandler(context);
    }
}
