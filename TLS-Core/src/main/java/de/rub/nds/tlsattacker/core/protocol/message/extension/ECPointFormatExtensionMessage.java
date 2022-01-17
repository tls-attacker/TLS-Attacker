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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC-ietf-tls-rfc-4492bis-17
 */
@XmlRootElement(name = "ECPointFormat")
public class ECPointFormatExtensionMessage extends ExtensionMessage<ECPointFormatExtensionMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
        super(ExtensionType.EC_POINT_FORMATS);
    }

    public ECPointFormatExtensionMessage(Config config) {
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
        this.pointFormatsLength = ModifiableVariableFactory.safelySetValue(pointFormatsLength, length);
    }

    public void setPointFormatsLength(ModifiableInteger pointFormatsLength) {
        this.pointFormatsLength = pointFormatsLength;
    }

    @Override
    public ECPointFormatExtensionParser getParser(TlsContext context, InputStream stream) {
        return new ECPointFormatExtensionParser(stream, context.getConfig());
    }

    @Override
    public ECPointFormatExtensionPreparator getPreparator(TlsContext context) {
        return new ECPointFormatExtensionPreparator(context.getChooser(), this, getSerializer(context));
    }

    @Override
    public ECPointFormatExtensionSerializer getSerializer(TlsContext context) {
        return new ECPointFormatExtensionSerializer(this);
    }

    @Override
    public ECPointFormatExtensionHandler getHandler(TlsContext context) {
        return new ECPointFormatExtensionHandler(context);
    }
}
