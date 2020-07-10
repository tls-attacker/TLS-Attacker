package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Random;

public class GreaseExtensionMessage extends ExtensionMessage {
    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] randomData;
    private byte[] type;

    public GreaseExtensionMessage() {
        super();
    }

    public GreaseExtensionMessage(ExtensionType type, byte[] data) {
        super(type);
        if (!type.name().startsWith("GREASE_")) {
            LOGGER.warn("GreaseExtension message inizialized with non Grease extension type");
        }
        this.type = type.getValue();
        this.randomData = data;
    }

    public GreaseExtensionMessage(ExtensionType type, int length) {
        super(type);
        if (!type.name().startsWith("GREASE_")) {
            LOGGER.warn("GreaseExtension message inizialized with non Grease extension type");
        }

        Random random = new Random(0);
        byte[] b = new byte[length];
        random.nextBytes(b);
        this.type = type.getValue();
        this.randomData = b;
    }

    @Override
    public ExtensionType getExtensionTypeConstant() {
        return ExtensionType.getExtensionType(this.type);
    }

    public byte[] getRandomData() {
        return randomData;
    }

    public void setRandomData(byte[] randomData) {
        this.randomData = randomData;
    }

    public byte[] getType() {
        return type;
    }

    public void setType(byte[] type) {
        this.type = type;
    }
}
