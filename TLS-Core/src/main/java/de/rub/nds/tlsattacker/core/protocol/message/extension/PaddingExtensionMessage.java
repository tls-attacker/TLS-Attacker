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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PaddingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PaddingExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC7685 */
@XmlRootElement(name = "PaddingExtension")
public class PaddingExtensionMessage extends ExtensionMessage<PaddingExtensionMessage> {

    /** Contains the padding bytes of the padding extension. The bytes shall be empty. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray paddingBytes;

    public PaddingExtensionMessage() {
        super(ExtensionType.PADDING);
    }

    public ModifiableByteArray getPaddingBytes() {
        return paddingBytes;
    }

    public void setPaddingBytes(ModifiableByteArray paddingBytes) {
        this.paddingBytes = paddingBytes;
    }

    public void setPaddingBytes(byte[] array) {
        this.paddingBytes = ModifiableVariableFactory.safelySetValue(paddingBytes, array);
    }

    @Override
    public PaddingExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PaddingExtensionParser(stream, tlsContext);
    }

    @Override
    public PaddingExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new PaddingExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PaddingExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new PaddingExtensionSerializer(this);
    }

    @Override
    public PaddingExtensionHandler getHandler(TlsContext tlsContext) {
        return new PaddingExtensionHandler(tlsContext);
    }
}
