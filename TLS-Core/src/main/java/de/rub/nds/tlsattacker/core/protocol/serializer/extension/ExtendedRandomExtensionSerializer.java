package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtendedRandomExtensionSerializer extends ExtensionSerializer<ExtendedRandomExtensionMessage>{

    private static final Logger LOGGER = LogManager.getLogger();
    private final ExtendedRandomExtensionMessage message;

    public ExtendedRandomExtensionSerializer(ExtendedRandomExtensionMessage message){
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getExtendedRandom().getValue());
        LOGGER.debug("Serialized Extended Random of length "
                + message.getExtendedRandom().getValue().length);
        return getAlreadySerialized();
    }
}
