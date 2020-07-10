package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.GreaseExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.GreaseExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class GreaseExtensionHandler extends ExtensionHandler<GreaseExtensionMessage> {

    public GreaseExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public GreaseExtensionParser getParser(byte[] message, int pointer) {
        return null;
    }

    @Override
    public GreaseExtensionPreparator getPreparator(GreaseExtensionMessage message) {
        return new GreaseExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public GreaseExtensionSerializer getSerializer(GreaseExtensionMessage message) {
        return new GreaseExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(GreaseExtensionMessage message) {

    }
}
