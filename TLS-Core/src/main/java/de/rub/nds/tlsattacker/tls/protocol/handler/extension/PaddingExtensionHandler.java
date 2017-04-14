/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionHandler extends ExtensionHandler<PaddingExtensionMessage> {

    public PaddingExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public PaddingExtensionParser getParser(byte[] message, int pointer) {
        return new PaddingExtensionParser(pointer, message);
    }

    @Override
    public PaddingExtensionPreparator getPreparator(PaddingExtensionMessage message) {
        return new PaddingExtensionPreparator(context, message);
    }

    @Override
    public PaddingExtensionSerializer getSerializer(PaddingExtensionMessage message) {
        return new PaddingExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(PaddingExtensionMessage message) {
        if (message.getPaddingLength().getValue() > 65535) {
            throw new AdjustmentException("Cannot set PaddingExtensionMode to a resonable Value");
        } else {
            context.setPaddingExtensionLength(message.getPaddingLength().getValue());
        }
    }

}
