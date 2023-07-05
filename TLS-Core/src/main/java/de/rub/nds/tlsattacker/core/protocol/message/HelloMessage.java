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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;

public abstract class HelloMessage<Self extends HelloMessage<?>> extends HandshakeMessage<Self> {

    /** protocol version in the client and server hello */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;
    /** unix time */
    @ModifiableVariableProperty private ModifiableByteArray unixTime;
    /** random */
    @ModifiableVariableProperty private ModifiableByteArray random;
    /** length of the session id length field indicating the session id length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger sessionIdLength;
    /** session id */
    @ModifiableVariableProperty private ModifiableByteArray sessionId;

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
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

    public void setProtocolVersion(byte[] array) {
        this.protocolVersion =
                ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    public void setUnixTime(ModifiableByteArray unixTime) {
        this.unixTime = unixTime;
    }

    public void setUnixTime(byte[] unixTime) {
        this.unixTime = ModifiableVariableFactory.safelySetValue(this.unixTime, unixTime);
    }

    public void setRandom(ModifiableByteArray random) {
        this.random = random;
    }

    public void setRandom(byte[] random) {
        this.random = ModifiableVariableFactory.safelySetValue(this.random, random);
    }

    public ModifiableInteger getSessionIdLength() {
        return sessionIdLength;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
        this.sessionIdLength = sessionIdLength;
    }

    public void setSessionIdLength(int sessionIdLength) {
        this.sessionIdLength =
                ModifiableVariableFactory.safelySetValue(this.sessionIdLength, sessionIdLength);
    }

    public void setSessionId(ModifiableByteArray sessionId) {
        this.sessionId = sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = ModifiableVariableFactory.safelySetValue(this.sessionId, sessionId);
    }
}
