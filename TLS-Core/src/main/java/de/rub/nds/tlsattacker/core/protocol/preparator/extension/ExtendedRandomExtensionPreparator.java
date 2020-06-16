package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
        if(chooser.getConnectionEndType().equals(ConnectionEndType.CLIENT)){
            message.setExtendedRandom(chooser.getClientExtendedRandom());
            LOGGER.debug("Prepared the Client Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
        }
        if(chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)){
            message.setExtendedRandom(chooser.getServerExtendedRandom());
            LOGGER.debug("Prepared the Server Extended Random with value "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom().getValue()));
        }
    }
}
