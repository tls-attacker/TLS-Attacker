/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptedServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptedServerNameIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "EncryptedServerNameIndicationExtension")
public class EncryptedServerNameIndicationExtensionMessage
        extends ExtensionMessage<EncryptedServerNameIndicationExtensionMessage> {

    private EsniMessageType esniMessageTypeConfig;

    @ModifiableVariableProperty private ModifiableByteArray cipherSuite;

    @HoldsModifiableVariable private KeyShareEntry keyShareEntry;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger recordDigestLength;

    @ModifiableVariableProperty private ModifiableByteArray recordDigest;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger encryptedSniLength;

    @ModifiableVariableProperty private ModifiableByteArray encryptedSni;

    @HoldsModifiableVariable private ClientEsniInner clientEsniInner;

    @ModifiableVariableProperty private ModifiableByteArray clientEsniInnerBytes;

    @HoldsModifiableVariable private EncryptedSniComputation encryptedSniComputation;

    @ModifiableVariableProperty private ModifiableByteArray serverNonce;

    public EncryptedServerNameIndicationExtensionMessage() {
        super(ExtensionType.ENCRYPTED_SERVER_NAME_INDICATION);
        this.keyShareEntry = new KeyShareEntry();
        this.clientEsniInner = new ClientEsniInner();
        this.encryptedSniComputation = new EncryptedSniComputation();
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

    public KeyShareEntry getKeyShareEntry() {
        return keyShareEntry;
    }

    public void setKeyShareEntry(KeyShareEntry keyShareEntry) {
        this.keyShareEntry = keyShareEntry;
    }

    public ModifiableInteger getRecordDigestLength() {
        return recordDigestLength;
    }

    public void setRecordDigestLength(ModifiableInteger recordDigestLength) {
        this.recordDigestLength = recordDigestLength;
    }

    public void setRecordDigestLength(int recordDigestLength) {
        this.recordDigestLength =
                ModifiableVariableFactory.safelySetValue(
                        this.recordDigestLength, recordDigestLength);
    }

    public ModifiableByteArray getRecordDigest() {
        return recordDigest;
    }

    public void setRecordDigest(ModifiableByteArray recordDigest) {
        this.recordDigest = recordDigest;
    }

    public void setRecordDigest(byte[] recordDigest) {
        this.recordDigest =
                ModifiableVariableFactory.safelySetValue(this.recordDigest, recordDigest);
    }

    public ModifiableInteger getEncryptedSniLength() {
        return encryptedSniLength;
    }

    public void setEncryptedSniLength(ModifiableInteger encryptedSniLength) {
        this.encryptedSniLength = encryptedSniLength;
    }

    public void setEncryptedSniLength(int encryptedSniLength) {
        this.encryptedSniLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedSniLength, encryptedSniLength);
    }

    public ModifiableByteArray getEncryptedSni() {
        return encryptedSni;
    }

    public void setEncryptedSni(ModifiableByteArray encryptedSni) {
        this.encryptedSni = encryptedSni;
    }

    public void setEncryptedSni(byte[] encryptedSni) {
        this.encryptedSni =
                ModifiableVariableFactory.safelySetValue(this.encryptedSni, encryptedSni);
    }

    public ClientEsniInner getClientEsniInner() {
        return clientEsniInner;
    }

    public void setClientEsniInner(ClientEsniInner clientEsniInner) {
        this.clientEsniInner = clientEsniInner;
    }

    public ModifiableByteArray getClientEsniInnerBytes() {
        return clientEsniInnerBytes;
    }

    public void setClientEsniInnerBytes(ModifiableByteArray clientEsniInnerBytes) {
        this.clientEsniInnerBytes = clientEsniInnerBytes;
    }

    public void setClientEsniInnerBytes(byte[] clientEsniInnerBytes) {
        this.clientEsniInnerBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.clientEsniInnerBytes, clientEsniInnerBytes);
    }

    public EncryptedSniComputation getEncryptedSniComputation() {
        return encryptedSniComputation;
    }

    public void setEncryptedSniComputation(EncryptedSniComputation encryptedSniComputation) {
        this.encryptedSniComputation = encryptedSniComputation;
    }

    public ModifiableByteArray getServerNonce() {
        return serverNonce;
    }

    public void setServerNonce(ModifiableByteArray serverNonce) {
        this.serverNonce = serverNonce;
    }

    public void setServerNonce(byte[] serverNonce) {
        this.serverNonce = ModifiableVariableFactory.safelySetValue(this.serverNonce, serverNonce);
    }

    public EsniMessageType getEsniMessageTypeConfig() {
        return esniMessageTypeConfig;
    }

    public void setEsniMessageTypeConfig(EsniMessageType esniMessageTypeConfig) {
        this.esniMessageTypeConfig = esniMessageTypeConfig;
    }

    @Override
    public EncryptedServerNameIndicationExtensionParser getParser(
            TlsContext tlsContext, InputStream stream) {
        return new EncryptedServerNameIndicationExtensionParser(stream, tlsContext);
    }

    @Override
    public EncryptedServerNameIndicationExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new EncryptedServerNameIndicationExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EncryptedServerNameIndicationExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new EncryptedServerNameIndicationExtensionSerializer(this);
    }

    @Override
    public EncryptedServerNameIndicationExtensionHandler getHandler(TlsContext tlsContext) {
        return new EncryptedServerNameIndicationExtensionHandler(tlsContext);
    }

    public enum EsniMessageType {
        CLIENT,
        SERVER;
    }
}
