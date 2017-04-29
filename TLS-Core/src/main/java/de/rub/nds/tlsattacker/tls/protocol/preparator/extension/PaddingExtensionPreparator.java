/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionPreparator extends ExtensionPreparator<PaddingExtensionMessage> {

    private final PaddingExtensionMessage message;

    public PaddingExtensionPreparator(TlsContext context, PaddingExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    /**
     * Prepares the padding extension padding bytes based on the length set in
     * the context.
     */
    @Override
    public void prepareExtensionContent() {
        message.setPaddingBytes(new byte[context.getConfig().getDefaultPaddingExtensionLength()]);
        LOGGER.debug("Prepared PaddingExtension with " + context.getConfig().getDefaultPaddingExtensionLength()
                + " padding bytes.");
    }

}
