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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedRandomExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Class representing a Extended Random Extension Message, as defined as in <a
 * href="https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02">draft-rescorla-tls-extended-random-02</a>
 */
@XmlRootElement(name = "ExtendedRandomExtension")
public class ExtendedRandomExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableByteArray extendedRandom;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger extendedRandomLength;

    public ExtendedRandomExtensionMessage() {
        super(ExtensionType.EXTENDED_RANDOM);
    }

    public void setExtendedRandom(ModifiableByteArray extendedRandom) {
        this.extendedRandom = extendedRandom;
    }

    public void setExtendedRandom(byte[] extendedRandomBytes) {
        this.extendedRandom =
                ModifiableVariableFactory.safelySetValue(extendedRandom, extendedRandomBytes);
    }

    public ModifiableByteArray getExtendedRandom() {
        return extendedRandom;
    }

    public ModifiableInteger getExtendedRandomLength() {
        return extendedRandomLength;
    }

    public void setExtendedRandomLength(int length) {
        this.extendedRandomLength =
                ModifiableVariableFactory.safelySetValue(extendedRandomLength, length);
    }

    public void setExtendedRandomLength(ModifiableInteger pointFormatsLength) {
        this.extendedRandomLength = pointFormatsLength;
    }

    @Override
    public ExtendedRandomExtensionParser getParser(Context context, InputStream stream) {
        return new ExtendedRandomExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public ExtendedRandomExtensionPreparator getPreparator(Context context) {
        return new ExtendedRandomExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public ExtendedRandomExtensionSerializer getSerializer(Context context) {
        return new ExtendedRandomExtensionSerializer(this);
    }

    @Override
    public ExtendedRandomExtensionHandler getHandler(Context context) {
        return new ExtendedRandomExtensionHandler(context.getTlsContext());
    }
}
