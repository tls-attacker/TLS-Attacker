/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECPointFormatExtensionPreparator extends ExtensionPreparator<ECPointFormatExtensionMessage> {

    private final ECPointFormatExtensionMessage message;

    public ECPointFormatExtensionPreparator(TlsContext context, ECPointFormatExtensionMessage message) {
        super(context, message);
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
        for (ECPointFormat format : context.getConfig().getPointFormats()) {
            stream.write(format.getValue());
        }
        return stream.toByteArray();
    }

}
