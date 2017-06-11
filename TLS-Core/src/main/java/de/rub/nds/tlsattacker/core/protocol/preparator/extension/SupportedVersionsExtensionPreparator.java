/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class SupportedVersionsExtensionPreparator extends ExtensionPreparator<SupportedVersionsExtensionMessage> {

    private SupportedVersionsExtensionMessage message;

    public SupportedVersionsExtensionPreparator(TlsContext context, SupportedVersionsExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        prepareProtocolVersions();
        message.setSupportedVersionsLength(message.getSupportedVersions().getValue().length);
    }

    private void prepareProtocolVersions() {
        message.setSupportedVersions(createProtocolVersionArray());
    }

    private byte[] createProtocolVersionArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ProtocolVersion version : context.getConfig().getSupportedVersions()) {
            try {
                stream.write(version.getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write ProtocolVersion to byte[]", ex);
            }
        }
        return stream.toByteArray();
    }
}