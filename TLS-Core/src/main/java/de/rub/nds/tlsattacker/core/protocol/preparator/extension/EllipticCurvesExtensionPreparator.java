/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EllipticCurvesExtensionPreparator
        extends ExtensionPreparator<EllipticCurvesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EllipticCurvesExtensionMessage msg;

    public EllipticCurvesExtensionPreparator(
            Chooser chooser, EllipticCurvesExtensionMessage message) {
        super(chooser, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EllipticCurvesExtensionMessage");
        prepareSupportedGroups(msg);
        prepareSupportedGroupsLength(msg);
    }

    private void prepareSupportedGroups(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedGroups(createNamedGroupsArray());
        LOGGER.debug("SupportedGroups: {}", msg.getSupportedGroups().getValue());
    }

    private byte[] createNamedGroupsArray() {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        List<NamedGroup> namedGroups;
        if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
            namedGroups = chooser.getConfig().getDefaultClientNamedGroups();
        } else {
            namedGroups = chooser.getConfig().getDefaultServerNamedGroups();
        }
        for (NamedGroup group : namedGroups) {
            stream.write(group.getValue());
        }
        return stream.toByteArray();
    }

    private void prepareSupportedGroupsLength(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedGroupsLength(msg.getSupportedGroups().getValue().length);
        LOGGER.debug("SupportedGroupsLength: {}", msg.getSupportedGroupsLength().getValue());
    }
}
