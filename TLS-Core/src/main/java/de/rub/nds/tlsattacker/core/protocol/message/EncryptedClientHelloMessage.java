/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedClientHelloSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;

@XmlRootElement(name = "EncryptedClientHello")
public class EncryptedClientHelloMessage
        extends CoreClientHelloMessage<EncryptedClientHelloMessage> {

    @HoldsModifiableVariable ClientHelloMessage clientHelloInner;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    private ModifiableByteArray encodedClientHelloInnerPadding;

    @XmlTransient
    private final EncryptedClientHelloExtensionMessage encryptedClientHelloExtensionMessage;

    public EncryptedClientHelloMessage() {
        super();
        encryptedClientHelloExtensionMessage =
                new EncryptedClientHelloExtensionMessage(EchClientHelloType.OUTER);
        addExtension(encryptedClientHelloExtensionMessage);
    }

    public EncryptedClientHelloMessage(Config tlsConfig) {
        super(tlsConfig);
        encryptedClientHelloExtensionMessage =
                new EncryptedClientHelloExtensionMessage(EchClientHelloType.OUTER);
        addExtension(encryptedClientHelloExtensionMessage);
    }

    @Override
    public EncryptedClientHelloHandler getHandler(TlsContext context) {
        return new EncryptedClientHelloHandler(context);
    }

    @Override
    public EncryptedClientHelloParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EncryptedClientHelloParser(stream, tlsContext);
    }

    @Override
    public EncryptedClientHelloPreparator getPreparator(TlsContext tlsContext) {
        return new EncryptedClientHelloPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EncryptedClientHelloSerializer getSerializer(TlsContext tlsContext) {
        return new EncryptedClientHelloSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    public ClientHelloMessage getClientHelloInner() {
        return clientHelloInner;
    }

    public void setClientHelloInner(ClientHelloMessage clientHelloInner) {
        this.clientHelloInner = clientHelloInner;
    }

    public ModifiableByteArray getEncodedClientHelloInnerPadding() {
        return encodedClientHelloInnerPadding;
    }

    public void setEncodedClientHelloInnerPadding(
            ModifiableByteArray encodedClientHelloInnerPadding) {
        this.encodedClientHelloInnerPadding = encodedClientHelloInnerPadding;
    }

    public void setEncodedClientHelloInnerPadding(byte[] encodedClientHelloInnerPadding) {
        this.encodedClientHelloInnerPadding =
                ModifiableVariableFactory.safelySetValue(
                        this.encodedClientHelloInnerPadding, encodedClientHelloInnerPadding);
    }

    public EncryptedClientHelloExtensionMessage getEncryptedClientHelloExtensionMessage() {
        return encryptedClientHelloExtensionMessage;
    }

    @Override
    public String toShortString() {
        return "ECH";
    }
}
