/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the EllipticCurves extensions, as defined in <a
 * href="https://tools.ietf.org/search/rfc4492#section-5.1.1">RFC 4492 Section 5.1.1</a>
 *
 * <p>But in TLS 1.3 this extensions renamed to SupportedGroups.
 *
 * <p>See: <a
 * href="https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.6">draft-ietf-tls-tls13-21
 * Section 4.2.6</a>
 */
public class EllipticCurvesExtensionHandler
        extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EllipticCurvesExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(EllipticCurvesExtensionMessage message) {
        byte[] groupBytes = message.getSupportedGroups().getValue();
        if (groupBytes.length % NamedGroup.LENGTH != 0) {
            throw new AdjustmentException(
                    "Could not create reasonable NamedGroups from groupBytes");
        }
        List<NamedGroup> groupList = new LinkedList<>();
        for (int i = 0; i < groupBytes.length; i += NamedGroup.LENGTH) {
            byte[] group = Arrays.copyOfRange(groupBytes, i, i + NamedGroup.LENGTH);
            NamedGroup namedGroup = NamedGroup.getNamedGroup(group);
            if (namedGroup == null) {
                LOGGER.warn("Unknown EllipticCurve: {}", group);
            } else {
                groupList.add(namedGroup);
            }
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientNamedGroupsList(groupList);
        } else {
            tlsContext.setServerNamedGroupsList(groupList);
        }
    }
}
