/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptedClientHelloExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptedClientHelloExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedClientHelloExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedClientHelloExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** The encrypted client hello extension sent by the client */
@XmlRootElement(name = "EncryptedClientHelloExtension")
public class EncryptedClientHelloExtensionMessage extends ExtensionMessage {

    private EchClientHelloType echClientHelloType;

    private HpkeCipherSuite hpkeCipherSuite;

    @ModifiableVariableProperty private ModifiableInteger configId;

    @ModifiableVariableProperty private ModifiableInteger encLength;

    @ModifiableVariableProperty private ModifiableByteArray enc;

    @ModifiableVariableProperty private ModifiableInteger payloadLength;

    @ModifiableVariableProperty private ModifiableByteArray payload;

    private ModifiableByteArray acceptConfirmation;

    public EncryptedClientHelloExtensionMessage() {
        super(ExtensionType.ENCRYPTED_CLIENT_HELLO);
    }

    public EncryptedClientHelloExtensionMessage(EchClientHelloType clientHelloType) {
        super(ExtensionType.ENCRYPTED_CLIENT_HELLO);
        echClientHelloType = clientHelloType;
    }

    @Override
    public EncryptedClientHelloExtensionParser getParser(Context context, InputStream stream) {
        return new EncryptedClientHelloExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public EncryptedClientHelloExtensionPreparator getPreparator(Context context) {
        return new EncryptedClientHelloExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public EncryptedClientHelloExtensionSerializer getSerializer(Context context) {
        return new EncryptedClientHelloExtensionSerializer(this);
    }

    @Override
    public ExtensionHandler<EncryptedClientHelloExtensionMessage> getHandler(Context context) {
        return new EncryptedClientHelloExtensionHandler(context.getTlsContext());
    }

    public EchClientHelloType getEchClientHelloType() {
        return echClientHelloType;
    }

    public void setEchClientHelloType(EchClientHelloType echClientHelloType) {
        this.echClientHelloType = echClientHelloType;
    }

    public HpkeCipherSuite getHpkeCipherSuite() {
        return hpkeCipherSuite;
    }

    public void setHpkeCipherSuite(HpkeCipherSuite hpkeCipherSuite) {
        this.hpkeCipherSuite = hpkeCipherSuite;
    }

    public ModifiableInteger getConfigId() {
        return configId;
    }

    public void setConfigId(ModifiableInteger configId) {
        this.configId = configId;
    }

    public void setConfigId(int configId) {
        this.configId = ModifiableVariableFactory.safelySetValue(this.configId, configId);
    }

    public ModifiableByteArray getEnc() {
        return enc;
    }

    public void setEnc(ModifiableByteArray enc) {
        this.enc = enc;
    }

    public void setEnc(byte[] enc) {
        this.enc = ModifiableVariableFactory.safelySetValue(this.enc, enc);
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public ModifiableInteger getEncLength() {
        return encLength;
    }

    public void setEncLength(ModifiableInteger encLength) {
        this.encLength = encLength;
    }

    public void setEncLength(int encLength) {
        this.encLength = ModifiableVariableFactory.safelySetValue(this.encLength, encLength);
    }

    public ModifiableInteger getPayloadLength() {
        return payloadLength;
    }

    public void setPayloadLength(ModifiableInteger payloadLength) {
        this.payloadLength = payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
        this.payloadLength =
                ModifiableVariableFactory.safelySetValue(this.payloadLength, payloadLength);
    }

    public ModifiableByteArray getAcceptConfirmation() {
        return acceptConfirmation;
    }

    public void setAcceptConfirmation(ModifiableByteArray acceptConfirmation) {
        this.acceptConfirmation = acceptConfirmation;
    }

    public void setAcceptConfirmation(byte[] acceptConfirmation) {
        this.acceptConfirmation =
                ModifiableVariableFactory.safelySetValue(
                        this.acceptConfirmation, acceptConfirmation);
    }
}
