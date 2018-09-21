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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EllipticCurvesExtensionPreparator extends ExtensionPreparator<EllipticCurvesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EllipticCurvesExtensionMessage msg;

    public EllipticCurvesExtensionPreparator(Chooser chooser, EllipticCurvesExtensionMessage message,
            EllipticCurvesExtensionSerializer serializer) {
        super(chooser, message, serializer);
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
        LOGGER.debug("SupportedGroups: " + ArrayConverter.bytesToHexString(msg.getSupportedGroups().getValue()));
    }

    private byte[] createNamedGroupsArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        List<NamedGroup> namedGroups;
        if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
            namedGroups = chooser.getConfig().getDefaultClientNamedGroups();
        } else {
            namedGroups = chooser.getConfig().getDefaultServerNamedGroups();
        }
        for (NamedGroup group : namedGroups) {
            try {
                stream.write(group.getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write NamedGroup to byte[]", ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareSupportedGroupsLength(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedGroupsLength(msg.getSupportedGroups().getValue().length);
        LOGGER.debug("SupportedGroupsLength: " + msg.getSupportedGroupsLength().getValue());
    }
}
