/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC6091
 */
@XmlRootElement(name = "CertificateTypeExtension")
public class CertificateTypeExtensionMessage extends ExtensionMessage<CertificateTypeExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableInteger certificateTypesLength;
    @ModifiableVariableProperty
    private ModifiableByteArray certificateTypes;
    @ModifiableVariableProperty
    private ModifiableBoolean isClientMessage;

    public CertificateTypeExtensionMessage() {
        super(ExtensionType.CERT_TYPE);
    }

    public ModifiableInteger getCertificateTypesLength() {
        return certificateTypesLength;
    }

    public void setCertificateTypesLength(ModifiableInteger certificateTypesLength) {
        this.certificateTypesLength = certificateTypesLength;
    }

    public void setCertificateTypesLength(int certificateTypesLength) {
        this.certificateTypesLength =
            ModifiableVariableFactory.safelySetValue(this.certificateTypesLength, certificateTypesLength);
    }

    public ModifiableByteArray getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(ModifiableByteArray certificateTypes) {
        this.certificateTypes = certificateTypes;
    }

    public void setCertificateTypes(byte[] certificateTypes) {
        this.certificateTypes = ModifiableVariableFactory.safelySetValue(this.certificateTypes, certificateTypes);
    }

    public ModifiableBoolean getIsClientMessage() {
        return isClientMessage;
    }

    public void setIsClientMessage(ModifiableBoolean isClientMessage) {
        this.isClientMessage = isClientMessage;
    }

    public void setIsClientMessage(boolean isClientMessage) {
        this.isClientMessage = ModifiableVariableFactory.safelySetValue(this.isClientMessage, isClientMessage);
    }

    @Override
    public CertificateTypeExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateTypeExtensionParser(stream);
    }

    @Override
    public CertificateTypeExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new CertificateTypeExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CertificateTypeExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new CertificateTypeExtensionSerializer(this);
    }

    @Override
    public CertificateTypeExtensionHandler getHandler(TlsContext context) {
        return new CertificateTypeExtensionHandler(context);
    }

}
