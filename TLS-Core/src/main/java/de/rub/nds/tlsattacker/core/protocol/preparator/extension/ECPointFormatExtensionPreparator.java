/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECPointFormatExtensionPreparator extends ExtensionPreparator<ECPointFormatExtensionMessage> {

    private final ECPointFormatExtensionMessage message;

    public ECPointFormatExtensionPreparator(Chooser chooser, ECPointFormatExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {

        preparePointFormats();
        message.setPointFormatsLength(message.getPointFormats().getValue().length);
    }

    private void preparePointFormats() {
        message.setPointFormats(createPointFormatsByteArray());
    }

    private byte[] createPointFormatsByteArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        List<ECPointFormat> pointFormatList;
        if (chooser.getConfig().getConnectionEnd() == ConnectionEnd.CLIENT) {
            pointFormatList = chooser.getClientSupportedPointFormats();
        } else {
            pointFormatList = chooser.getServerSupportedPointFormats();
        }
        for (ECPointFormat format : pointFormatList) {
            stream.write(format.getValue());
        }
        return stream.toByteArray();
    }

}
