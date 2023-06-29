/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupportedVersionsExtensionPreparator
        extends ExtensionPreparator<SupportedVersionsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SupportedVersionsExtensionMessage msg;

    public SupportedVersionsExtensionPreparator(
            Chooser chooser, SupportedVersionsExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing SupportedVersionsExtensionMessage");
        prepareProtocolVersions(msg);
        if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
            prepareProtocolVersionsLength(msg);
        }
    }

    private void prepareProtocolVersions(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersions(createProtocolVersionArray());
        LOGGER.debug("SupportedVersions: {}", msg.getSupportedVersions().getValue());
    }

    private void prepareProtocolVersionsLength(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersionsLength(msg.getSupportedVersions().getValue().length);
        LOGGER.debug("SupportedVersionsLength: " + msg.getSupportedVersionsLength().getValue());
    }

    private byte[] createProtocolVersionArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ProtocolVersion version : chooser.getConfig().getSupportedVersions()) {
            try {
                stream.write(version.getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write ProtocolVersion to byte[]", ex);
            }
        }
        return stream.toByteArray();
    }
}
