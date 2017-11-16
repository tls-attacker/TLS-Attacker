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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;

public abstract class HelloMessage extends HandshakeMessage {

    /**
     * protocol version in the client and server hello
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;
    /**
     * unix time
     */
    @ModifiableVariableProperty
    private ModifiableByteArray unixTime;
    /**
     * random
     */
    @ModifiableVariableProperty
    private ModifiableByteArray random;
    /**
     * length of the session id length field indicating the session id length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIdLength;
    /**
     * session id
     */
    @ModifiableVariableProperty
    private ModifiableByteArray sessionId;

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
    }

    public HelloMessage(Config tlsConfig, HandshakeMessageType handshakeMessageType) {
        super(tlsConfig, handshakeMessageType);

    }

    public ModifiableByteArray getRandom() {
        return random;
    }

    public ModifiableByteArray getSessionId() {
        return sessionId;
    }

    public ModifiableByteArray getUnixTime() {
        return unixTime;
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setUnixTime(ModifiableByteArray unixTime) {
        this.unixTime = unixTime;
    }

    public void setRandom(ModifiableByteArray random) {
        this.random = random;
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
        this.sessionIdLength = sessionIdLength;
    }

    public void setSessionId(ModifiableByteArray sessionId) {
        this.sessionId = sessionId;
    }

    public void setRandom(byte[] random) {
        this.random = ModifiableVariableFactory.safelySetValue(this.random, random);
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = ModifiableVariableFactory.safelySetValue(this.sessionId, sessionId);
    }

    public void setUnixTime(byte[] unixTime) {
        this.unixTime = ModifiableVariableFactory.safelySetValue(this.unixTime, unixTime);
    }

    public void setSessionIdLength(int sessionIdLength) {
        this.sessionIdLength = ModifiableVariableFactory.safelySetValue(this.sessionIdLength, sessionIdLength);
    }

    public void setProtocolVersion(byte[] array) {
        this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

}
