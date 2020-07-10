package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;

public class GreaseExtensionSerializer extends ExtensionSerializer<GreaseExtensionMessage> {

    private final GreaseExtensionMessage msg;

    public GreaseExtensionSerializer(GreaseExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(msg.getRandomData());
        return getAlreadySerialized();
    }
}
