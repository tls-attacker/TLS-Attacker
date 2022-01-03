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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Random;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "GreaseExtension")
public class GreaseExtensionMessage extends ExtensionMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty
    private ModifiableByteArray randomData;

    private byte[] data;
    private ExtensionType type;

    public GreaseExtensionMessage() {
        super(ExtensionType.GREASE_00);
        this.type = ExtensionType.GREASE_00;
        data = new byte[0];
    }

    public GreaseExtensionMessage(Config config) {
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

    public void setType(ExtensionType type) {
        this.type = type;
    }
}
