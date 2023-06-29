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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerCertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerCertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerCertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerCertificateTypeExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC7250 */
@XmlRootElement(name = "ServerCertificateTypeExtension")
public class ServerCertificateTypeExtensionMessage
        extends ExtensionMessage<ServerCertificateTypeExtensionMessage> {

    @ModifiableVariableProperty private ModifiableInteger certificateTypesLength;
    @ModifiableVariableProperty private ModifiableByteArray certificateTypes;
    @ModifiableVariableProperty private ModifiableBoolean isClientMessage;

    public ServerCertificateTypeExtensionMessage() {
        super(ExtensionType.SERVER_CERTIFICATE_TYPE);
    }

    public ModifiableInteger getCertificateTypesLength() {
        return certificateTypesLength;
    }

    public void setCertificateTypesLength(ModifiableInteger certificateTypesLength) {
        this.certificateTypesLength = certificateTypesLength;
    }

    public void setCertificateTypesLength(int certificateTypesLength) {
        this.certificateTypesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.certificateTypesLength, certificateTypesLength);
    }

    public ModifiableByteArray getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(ModifiableByteArray certificateTypes) {
        this.certificateTypes = certificateTypes;
    }

    public void setCertificateTypes(byte[] certificateTypes) {
        this.certificateTypes =
                ModifiableVariableFactory.safelySetValue(this.certificateTypes, certificateTypes);
    }

    public ModifiableBoolean getIsClientMessage() {
        return isClientMessage;
    }

    public void setIsClientMessage(ModifiableBoolean isClientMessage) {
        this.isClientMessage = isClientMessage;
    }

    public void setIsClientMessage(boolean isClientMessage) {
        this.isClientMessage =
                ModifiableVariableFactory.safelySetValue(this.isClientMessage, isClientMessage);
    }

    @Override
    public ServerCertificateTypeExtensionParser getParser(
            TlsContext tlsContext, InputStream stream) {
        return new ServerCertificateTypeExtensionParser(stream, tlsContext);
    }

    @Override
    public ServerCertificateTypeExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ServerCertificateTypeExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ServerCertificateTypeExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ServerCertificateTypeExtensionSerializer(this);
    }

    @Override
    public ServerCertificateTypeExtensionHandler getHandler(TlsContext tlsContext) {
        return new ServerCertificateTypeExtensionHandler(tlsContext);
    }
}
