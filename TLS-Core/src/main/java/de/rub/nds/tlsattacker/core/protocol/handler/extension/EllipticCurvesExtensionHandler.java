/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EllipticCurvesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EllipticCurvesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the EllipticCurves extensions, as defined in
 * https://tools.ietf.org/search/rfc4492#section-5.1.1
 *
 * But in TLS 1.3 this extensions renamed to SupportedGroups.
 *
 * See: https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.6
 */
public class EllipticCurvesExtensionHandler extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EllipticCurvesExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(EllipticCurvesExtensionMessage message) {
        byte[] groupBytes = message.getSupportedGroups().getValue();
        if (groupBytes.length % NamedGroup.LENGTH != 0) {
            throw new AdjustmentException("Could not create resonable NamedGroups from groupBytes");
        }
        List<NamedGroup> groupList = new LinkedList<>();
        for (int i = 0; i < groupBytes.length; i += NamedGroup.LENGTH) {
            byte[] group = Arrays.copyOfRange(groupBytes, i, i + NamedGroup.LENGTH);
            NamedGroup namedGroup = NamedGroup.getNamedGroup(group);
            if (namedGroup == null) {
                LOGGER.warn("Unknown EllipticCruve:" + ArrayConverter.bytesToHexString(group));
            } else {
                groupList.add(namedGroup);
            }
        }
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            context.setClientNamedGroupsList(groupList);
        } else {
            context.setServerNamedGroupsList(groupList);
        }
    }

    @Override
    public EllipticCurvesExtensionParser getParser(byte[] message, int pointer) {
        return new EllipticCurvesExtensionParser(pointer, message);
    }

    @Override
    public EllipticCurvesExtensionPreparator getPreparator(EllipticCurvesExtensionMessage message) {
        return new EllipticCurvesExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public EllipticCurvesExtensionSerializer getSerializer(EllipticCurvesExtensionMessage message) {
        return new EllipticCurvesExtensionSerializer(message);
    }
}
