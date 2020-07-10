package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;

public class GreaseExtensionParser extends ExtensionParser<GreaseExtensionMessage> {
    public GreaseExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(GreaseExtensionMessage msg) {
        parseByteArrayField(msg.getExtensionLength().getValue());
    }

    @Override
    protected GreaseExtensionMessage createExtensionMessage() {
        return new GreaseExtensionMessage();
    }
}
