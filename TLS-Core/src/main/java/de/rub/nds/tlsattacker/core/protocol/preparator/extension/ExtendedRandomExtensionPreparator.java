package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtendedRandomExtensionPreparator extends ExtensionPreparator<ExtendedRandomExtensionMessage>{

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtendedRandomExtensionMessage message;

    public ExtendedRandomExtensionPreparator(Chooser chooser, ExtendedRandomExtensionMessage message, ExtendedRandomExtensionSerializer serializer){
        super(chooser, message, serializer);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setExtendedRandom(chooser.getConfig().getExtendedRandom());
        LOGGER.debug("Prepared the Extended Random with value "
                + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
    }
}
