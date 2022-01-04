/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

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
            throw new AdjustmentException("Could not create reasonable NamedGroups from groupBytes");
        }
        List<NamedGroup> groupList = new LinkedList<>();
        for (int i = 0; i < groupBytes.length; i += NamedGroup.LENGTH) {
            byte[] group = Arrays.copyOfRange(groupBytes, i, i + NamedGroup.LENGTH);
            NamedGroup namedGroup = NamedGroup.getNamedGroup(group);
            if (namedGroup == null) {
                LOGGER.warn("Unknown EllipticCurve:" + ArrayConverter.bytesToHexString(group));
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

}
