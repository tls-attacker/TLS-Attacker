package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GreaseExtensionPreparator extends ExtensionPreparator<GreaseExtensionMessage> {
    public GreaseExtensionPreparator(Chooser chooser, GreaseExtensionMessage message, ExtensionSerializer<GreaseExtensionMessage> serializer) {
        super(chooser, message, serializer);
    }

    @Override
    public void prepareExtensionContent() {

    }
}
