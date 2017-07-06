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
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ClientHelloHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
@XmlRootElement
public class SSL2ClientHelloMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;

    @ModifiableVariableProperty
    private ModifiableByte type;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cipherSuiteLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIDLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger challengeLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;

    private ModifiableByteArray sessionID;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray challenge;

    public SSL2ClientHelloMessage() {
    }

    public SSL2ClientHelloMessage(TlsConfig config) {
        super();
    }

    @Override
    public String toCompactString() {
        return "SSL2 ClientHello Message";
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new SSL2ClientHelloHandler(context);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(Integer messageLength) {
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

    public ModifiableInteger getSessionIDLength() {
        return sessionIDLength;
    }

    public void setSessionIDLength(ModifiableInteger sessionIDLength) {
        this.sessionIDLength = sessionIDLength;
    }

    public void setSessionIDLength(int sessionIDLength) {
        this.sessionIDLength = ModifiableVariableFactory.safelySetValue(this.sessionIDLength, sessionIDLength);
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
        // TODO
        return sb.toString();
    }
}
