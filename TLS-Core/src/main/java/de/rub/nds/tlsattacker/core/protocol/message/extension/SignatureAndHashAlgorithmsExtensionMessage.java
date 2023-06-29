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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAndHashAlgorithmsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAndHashAlgorithmsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC5246 */
@XmlRootElement(name = "SignatureAndHashAlgorithmsExtension")
public class SignatureAndHashAlgorithmsExtensionMessage
        extends ExtensionMessage<SignatureAndHashAlgorithmsExtensionMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmsExtensionMessage() {
        super(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS);
    }

    public ModifiableInteger getSignatureAndHashAlgorithmsLength() {
        return signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithmsLength(int length) {
        this.signatureAndHashAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.signatureAndHashAlgorithmsLength, length);
    }

    public void setSignatureAndHashAlgorithmsLength(
            ModifiableInteger signatureAndHashAlgorithmsLength) {
        this.signatureAndHashAlgorithmsLength = signatureAndHashAlgorithmsLength;
    }

    public ModifiableByteArray getSignatureAndHashAlgorithms() {
        return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(byte[] array) {
        this.signatureAndHashAlgorithms =
                ModifiableVariableFactory.safelySetValue(this.signatureAndHashAlgorithms, array);
    }

    public void setSignatureAndHashAlgorithms(ModifiableByteArray signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionParser getParser(
            TlsContext tlsContext, InputStream stream) {
        return new SignatureAndHashAlgorithmsExtensionParser(stream, tlsContext);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SignatureAndHashAlgorithmsExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SignatureAndHashAlgorithmsExtensionSerializer(this);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionHandler getHandler(TlsContext tlsContext) {
        return new SignatureAndHashAlgorithmsExtensionHandler(tlsContext);
    }
}
