/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.mlong.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;

public class StatePlaintext {
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableInteger cipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte compressionMethod;

    @ModifiableVariableProperty()
    private ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte clientAuthenticationType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger clientAuthenticationDataLength;

    @ModifiableVariableProperty()
    private ModifiableByteArray clientAuthenticationData;

    @ModifiableVariableProperty()
    private ModifiableLong timestamp;

    public StatePlaintext() {
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

    public ModifiableInteger getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(ModifiableInteger cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public void setCipherSuite(int cipherSuite) {
        this.cipherSuite = ModifiableVariableFactory.safelySetValue(this.cipherSuite, cipherSuite);
    }

    public ModifiableByte getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(ModifiableByte compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public void setCompressionMethod(byte compressionMethod) {
        this.compressionMethod = ModifiableVariableFactory.safelySetValue(this.compressionMethod, compressionMethod);
    }

    public ModifiableByteArray getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = ModifiableVariableFactory.safelySetValue(this.masterSecret, masterSecret);
    }

    public ModifiableByte getClientAuthenticationType() {
        return clientAuthenticationType;
    }

    public void setClientAuthenticationType(ModifiableByte clientAuthenticationType) {
        this.clientAuthenticationType = clientAuthenticationType;
    }

    public void setClientAuthenticationType(byte clientAuthenticationType) {
        this.clientAuthenticationType = ModifiableVariableFactory.safelySetValue(this.clientAuthenticationType,
                clientAuthenticationType);
    }

    public ModifiableInteger getClientAuthenticationDataLength() {
        return clientAuthenticationDataLength;
    }

    public void setClientAuthenticationDataLength(ModifiableInteger clientAuthenticationDataLength) {
        this.clientAuthenticationDataLength = clientAuthenticationDataLength;
    }

    public void setClientAuthenticationDataLength(int clientAuthenticationDataLength) {
        this.clientAuthenticationDataLength = ModifiableVariableFactory.safelySetValue(
                this.clientAuthenticationDataLength, clientAuthenticationDataLength);
    }

    public ModifiableByteArray getClientAuthenticationData() {
        return clientAuthenticationData;
    }

    public void setClientAuthenticationData(ModifiableByteArray clientAuthenticationData) {
        this.clientAuthenticationData = clientAuthenticationData;
    }

    public void setClientAuthenticationData(byte[] clientAuthenticationData) {
        this.clientAuthenticationData = ModifiableVariableFactory.safelySetValue(this.clientAuthenticationData,
                clientAuthenticationData);
    }

    public ModifiableLong getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(ModifiableLong timestamp) {
        this.timestamp = timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = ModifiableVariableFactory.safelySetValue(this.timestamp, timestamp);
    }
}
