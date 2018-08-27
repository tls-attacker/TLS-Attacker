/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECPointFormatExtensionPreparator extends ExtensionPreparator<ECPointFormatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ECPointFormatExtensionMessage msg;

    public ECPointFormatExtensionPreparator(Chooser chooser, ECPointFormatExtensionMessage message,
            ECPointFormatExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ECPointFormatExtensionMessage");
        preparePointFormats(msg);
        preparePointFormatsLength(msg);
    }

    private void preparePointFormats(ECPointFormatExtensionMessage msg) {
        msg.setPointFormats(createPointFormatsByteArray());
        LOGGER.debug("PointFormats: " + ArrayConverter.bytesToHexString(msg.getPointFormats().getValue()));
    }

    private byte[] createPointFormatsByteArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        List<ECPointFormat> pointFormatList;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            pointFormatList = chooser.getClientSupportedPointFormats();
        } else {
            pointFormatList = chooser.getServerSupportedPointFormats();
        }
        for (ECPointFormat format : pointFormatList) {
            stream.write(format.getValue());
        }
        return stream.toByteArray();
    }

    private void preparePointFormatsLength(ECPointFormatExtensionMessage msg) {
        msg.setPointFormatsLength(msg.getPointFormats().getValue().length);
        LOGGER.debug("PointFormatsLength: " + msg.getPointFormatsLength().getValue());
    }

}
