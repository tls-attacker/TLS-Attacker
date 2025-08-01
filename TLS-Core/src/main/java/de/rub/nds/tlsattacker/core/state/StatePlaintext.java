/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.util.TimeHelper;

public class StatePlaintext {
    @ModifiableVariableProperty private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty private ModifiableByteArray cipherSuite;

    @ModifiableVariableProperty private ModifiableByte compressionMethod;

    @ModifiableVariableProperty() private ModifiableByteArray masterSecret;

    @ModifiableVariableProperty private ModifiableByte clientAuthenticationType;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger clientAuthenticationDataLength;

    @ModifiableVariableProperty() private ModifiableByteArray clientAuthenticationData;

    @ModifiableVariableProperty() private ModifiableLong timestamp;

    public StatePlaintext() {}

    public void generateStatePlaintext(Chooser chooser) {
        setCipherSuite(chooser.getSelectedCipherSuite().getByteValue());
        setCompressionMethod(chooser.getSelectedCompressionMethod().getValue());
        setMasterSecret(chooser.getMasterSecret());
        setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());

        long timestamp = TimeHelper.getTime() / 1000;
        setTimestamp(timestamp);

        switch (chooser.getConfig().getClientAuthenticationType()) {
            case ANONYMOUS:
                setClientAuthenticationType(ClientAuthenticationType.ANONYMOUS.getValue());
                setClientAuthenticationData(new byte[0]);
                setClientAuthenticationDataLength(0);
                break;
            case CERTIFICATE_BASED:
                throw new UnsupportedOperationException(
                        "Certificate based ClientAuthentication is not supported");
            case PSK:
                throw new UnsupportedOperationException(
                        "PSK ClientAuthentication is not supported");
            default:
                throw new UnsupportedOperationException("Unknown ClientAuthenticationType");
        }
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

    public ModifiableByteArray getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(ModifiableByteArray cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public void setCipherSuite(byte[] cipherSuite) {
        this.cipherSuite = ModifiableVariableFactory.safelySetValue(this.cipherSuite, cipherSuite);
    }

    public ModifiableByte getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(ModifiableByte compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public void setCompressionMethod(byte compressionMethod) {
        this.compressionMethod =
                ModifiableVariableFactory.safelySetValue(this.compressionMethod, compressionMethod);
    }

    public ModifiableByteArray getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret =
                ModifiableVariableFactory.safelySetValue(this.masterSecret, masterSecret);
    }

    public ModifiableByte getClientAuthenticationType() {
        return clientAuthenticationType;
    }

    public void setClientAuthenticationType(ModifiableByte clientAuthenticationType) {
        this.clientAuthenticationType = clientAuthenticationType;
    }

    public void setClientAuthenticationType(byte clientAuthenticationType) {
        this.clientAuthenticationType =
                ModifiableVariableFactory.safelySetValue(
                        this.clientAuthenticationType, clientAuthenticationType);
    }

    public ModifiableInteger getClientAuthenticationDataLength() {
        return clientAuthenticationDataLength;
    }

    public void setClientAuthenticationDataLength(
            ModifiableInteger clientAuthenticationDataLength) {
        this.clientAuthenticationDataLength = clientAuthenticationDataLength;
    }

    public void setClientAuthenticationDataLength(int clientAuthenticationDataLength) {
        this.clientAuthenticationDataLength =
                ModifiableVariableFactory.safelySetValue(
                        this.clientAuthenticationDataLength, clientAuthenticationDataLength);
    }

    public ModifiableByteArray getClientAuthenticationData() {
        return clientAuthenticationData;
    }

    public void setClientAuthenticationData(ModifiableByteArray clientAuthenticationData) {
        this.clientAuthenticationData = clientAuthenticationData;
    }

    public void setClientAuthenticationData(byte[] clientAuthenticationData) {
        this.clientAuthenticationData =
                ModifiableVariableFactory.safelySetValue(
                        this.clientAuthenticationData, clientAuthenticationData);
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
