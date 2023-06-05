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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SupportedVersionsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SupportedVersionsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SupportedVersionsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "SupportedVersions")
public class SupportedVersionsExtensionMessage
        extends ExtensionMessage<SupportedVersionsExtensionMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedVersionsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedVersions;

    public SupportedVersionsExtensionMessage() {
        super(ExtensionType.SUPPORTED_VERSIONS);
    }

    public ModifiableInteger getSupportedVersionsLength() {
        return supportedVersionsLength;
    }

    public void setSupportedVersionsLength(int length) {
        this.supportedVersionsLength =
                ModifiableVariableFactory.safelySetValue(this.supportedVersionsLength, length);
    }

    public void setSupportedVersionsLength(ModifiableInteger supportedVersionsLength) {
        this.supportedVersionsLength = supportedVersionsLength;
    }

    public ModifiableByteArray getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(byte[] array) {
        this.supportedVersions =
                ModifiableVariableFactory.safelySetValue(this.supportedVersions, array);
    }

    public void setSupportedVersions(ModifiableByteArray supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    @Override
    public SupportedVersionsExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SupportedVersionsExtensionParser(stream, tlsContext);
    }

    @Override
    public SupportedVersionsExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SupportedVersionsExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SupportedVersionsExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SupportedVersionsExtensionSerializer(this);
    }

    @Override
    public SupportedVersionsExtensionHandler getHandler(TlsContext tlsContext) {
        return new SupportedVersionsExtensionHandler(tlsContext);
    }
}
