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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignatureAlgorithmsCertExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAlgorithmsCertExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAlgorithmsCertExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAlgorithmsCertExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC8446 */
@XmlRootElement(name = "SignatureAlgorithmsCertExtension")
public class SignatureAlgorithmsCertExtensionMessage extends ExtensionMessage {
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureAndHashAlgorithms;

    public SignatureAlgorithmsCertExtensionMessage() {
        super(ExtensionType.SIGNATURE_ALGORITHMS_CERT);
    }

    public SignatureAlgorithmsCertExtensionMessage(Config config) {
        super(ExtensionType.SIGNATURE_ALGORITHMS_CERT);
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
    public SignatureAlgorithmsCertExtensionHandler getHandler(Context context) {
        return new SignatureAlgorithmsCertExtensionHandler(context.getTlsContext());
    }

    @Override
    public SignatureAlgorithmsCertExtensionSerializer getSerializer(Context context) {
        return new SignatureAlgorithmsCertExtensionSerializer(this);
    }

    @Override
    public SignatureAlgorithmsCertExtensionPreparator getPreparator(Context context) {
        return new SignatureAlgorithmsCertExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public SignatureAlgorithmsCertExtensionParser getParser(Context context, InputStream stream) {
        return new SignatureAlgorithmsCertExtensionParser(stream, context.getTlsContext());
    }
}
