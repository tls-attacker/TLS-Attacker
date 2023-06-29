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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.GreaseExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.GreaseExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.GreaseExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "GreaseExtension")
public class GreaseExtensionMessage extends ExtensionMessage<GreaseExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty private ModifiableByteArray randomData;

    private byte[] data;
    private ExtensionType type;

    public GreaseExtensionMessage() {
        super(ExtensionType.GREASE_00);
        this.type = ExtensionType.GREASE_00;
        data = new byte[0];
    }

    public GreaseExtensionMessage(ExtensionType type, byte[] data) {
        super(type);
        if (!type.name().startsWith("GREASE_")) {
            LOGGER.warn("GreaseExtension message inizialized with non Grease extension type");
        }
        this.data = data;
        this.type = type;
    }

    public GreaseExtensionMessage(ExtensionType type, int length) {
        super(type);
        if (!type.name().startsWith("GREASE_")) {
            LOGGER.warn("GreaseExtension message inizialized with non Grease extension type");
        }

        Random random = new Random(0);
        byte[] b = new byte[length];
        random.nextBytes(b);
        this.data = b;
        this.type = type;
    }

    @Override
    public ExtensionType getExtensionTypeConstant() {
        return this.type;
    }

    public ModifiableByteArray getRandomData() {
        return randomData;
    }

    public void setRandomData(byte[] bytes) {
        this.randomData = ModifiableVariableFactory.safelySetValue(randomData, bytes);
    }

    public void setRandomData(ModifiableByteArray randomData) {
        this.randomData = randomData;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public ExtensionType getType() {
        return type;
    }

    @Override
    public GreaseExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new GreaseExtensionParser(stream, tlsContext);
    }

    @Override
    public GreaseExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new GreaseExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public GreaseExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new GreaseExtensionSerializer(this);
    }

    @Override
    public GreaseExtensionHandler getHandler(TlsContext tlsContext) {
        return new GreaseExtensionHandler(tlsContext);
    }
}
