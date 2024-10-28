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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC-ietf-tls-rfc-4492bis-17 */
@XmlRootElement(name = "ECPointFormat")
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
        super(ExtensionType.EC_POINT_FORMATS);
    }

    public ModifiableByteArray getPointFormats() {
        return pointFormats;
    }

    public void setPointFormats(byte[] array) {
        this.pointFormats = ModifiableVariableFactory.safelySetValue(pointFormats, array);
    }

    public void setPointFormats(ModifiableByteArray pointFormats) {
        this.pointFormats = pointFormats;
    }

    public ModifiableInteger getPointFormatsLength() {
        return pointFormatsLength;
    }

    public void setPointFormatsLength(int length) {
        this.pointFormatsLength =
                ModifiableVariableFactory.safelySetValue(pointFormatsLength, length);
    }

    public void setPointFormatsLength(ModifiableInteger pointFormatsLength) {
        this.pointFormatsLength = pointFormatsLength;
    }

    @Override
    public ECPointFormatExtensionParser getParser(Context context, InputStream stream) {
        return new ECPointFormatExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public ECPointFormatExtensionPreparator getPreparator(Context context) {
        return new ECPointFormatExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public ECPointFormatExtensionSerializer getSerializer(Context context) {
        return new ECPointFormatExtensionSerializer(this);
    }

    @Override
    public ECPointFormatExtensionHandler getHandler(Context context) {
        return new ECPointFormatExtensionHandler(context.getTlsContext());
    }
}
