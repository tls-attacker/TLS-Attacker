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
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import static de.rub.nds.tlsattacker.core.state.State.LOGGER;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Timon Wern <timon.wern@rub.de>
 */
public class StatePlaintext {
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion; // 2 Bytes

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableInteger cipherSuite; // 2 Bytes

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte compressionMethod; // 1 Byte

    @ModifiableVariableProperty()
    private ModifiableByteArray masterSecret; // 48 Bytes

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte clientAuthenticationType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger clientAuthenticationDataLength; // Anon 0 Bytes,
                                                              // PSK 2 Bytes,
                                                              // Certs 3 Bytes

    @ModifiableVariableProperty()
    private ModifiableByteArray clientAuthenticationData;

    @ModifiableVariableProperty()
    private ModifiableLong timestamp; // uint32

    public StatePlaintext() {
    }

    public byte[] serialize() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {

            // TODO: Should I check that the varables are set?
            outputStream.write(protocolVersion.getValue());
            outputStream.write(cipherSuite.getByteArray(HandshakeByteLength.CIPHER_SUITE));
            outputStream.write(compressionMethod.getValue());

            // https://tools.ietf.org/html/rfc5246#section-8.1
            // The master secret is always exactly 48 bytes in length.
            outputStream.write(masterSecret.getValue());

            // Check ClientAuthType for serialization
            if (clientAuthenticationType.getValue() == ClientAuthenticationType.ANONYMOUS.getValue()) {
                outputStream.write(clientAuthenticationType.getValue());
            } else if (clientAuthenticationType.getValue() == ClientAuthenticationType.CERTIFICATE_BASED.getValue()) {
                outputStream.write(clientAuthenticationType.getValue());
                outputStream
                        .write(clientAuthenticationDataLength.getByteArray(HandshakeByteLength.CERTIFICATES_LENGTH));
                outputStream.write(clientAuthenticationData.getValue());
            } else if (clientAuthenticationType.getValue() == ClientAuthenticationType.PSK.getValue()) {
                outputStream.write(clientAuthenticationType.getValue());
                outputStream
                        .write(clientAuthenticationDataLength.getByteArray(HandshakeByteLength.PSK_IDENTITY_LENGTH));
                outputStream.write(clientAuthenticationData.getValue());
            } else {
                outputStream.write(clientAuthenticationType.getValue());
                LOGGER.warn("Can't serialize ClientAuthticationData because the choosen ClientAuthType is unknown: "
                        + clientAuthenticationType.getValue());
            }

            outputStream.write(timestamp.getByteArray(4));
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        return outputStream.toByteArray();
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
