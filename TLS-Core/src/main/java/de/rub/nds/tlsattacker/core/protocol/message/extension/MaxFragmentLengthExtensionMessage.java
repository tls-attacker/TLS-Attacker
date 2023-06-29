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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.MaxFragmentLengthExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.MaxFragmentLengthExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.MaxFragmentLengthExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Maximum Fragment Length Extension described in rfc3546 */
@XmlRootElement(name = "MaxFragmentLengthExtension")
public class MaxFragmentLengthExtensionMessage
        extends ExtensionMessage<MaxFragmentLengthExtensionMessage> {

    private MaxFragmentLength maxFragmentLengthConfig;

    /** Maximum fragment length value described in rfc3546 */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray maxFragmentLength;

    public MaxFragmentLengthExtensionMessage() {
        super(ExtensionType.MAX_FRAGMENT_LENGTH);
    }

    public ModifiableByteArray getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(ModifiableByteArray maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    public void setMaxFragmentLength(byte[] maxFragmentLength) {
        this.maxFragmentLength =
                ModifiableVariableFactory.safelySetValue(this.maxFragmentLength, maxFragmentLength);
    }

    @Override
    public MaxFragmentLengthExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new MaxFragmentLengthExtensionParser(stream, tlsContext);
    }

    @Override
    public MaxFragmentLengthExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new MaxFragmentLengthExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public MaxFragmentLengthExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new MaxFragmentLengthExtensionSerializer(this);
    }

    @Override
    public MaxFragmentLengthExtensionHandler getHandler(TlsContext tlsContext) {
        return new MaxFragmentLengthExtensionHandler(tlsContext);
    }
}
