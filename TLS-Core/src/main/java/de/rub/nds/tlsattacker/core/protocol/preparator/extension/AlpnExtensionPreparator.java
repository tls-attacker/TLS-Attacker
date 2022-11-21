/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.alpn.AlpnEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.alpn.AlpnEntrySerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlpnExtensionPreparator extends ExtensionPreparator<AlpnExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AlpnExtensionMessage msg;

    public AlpnExtensionPreparator(Chooser chooser, AlpnExtensionMessage message,
        ExtensionSerializer<AlpnExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        List<AlpnEntry> alpnEntryList = new LinkedList<>();
        if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
            List<String> alpnStringList = chooser.getConfig().getDefaultProposedAlpnProtocols();
            for (String alpnProtocol : alpnStringList) {
                alpnEntryList.add(new AlpnEntry(alpnProtocol));
            }
        } else {
            if (chooser.getConfig().isEnforceSettings()) {
                alpnEntryList.add(new AlpnEntry(chooser.getConfig().getDefaultSelectedAlpnProtocol()));
                LOGGER.debug("Enforce settings is active: Selected ALPN protocol is "
                    + chooser.getConfig().getDefaultSelectedAlpnProtocol());
            } else {
                List<String> proposedAlpnProtocols = chooser.getProposedAlpnProtocols();
                if (proposedAlpnProtocols.contains(chooser.getConfig().getDefaultSelectedAlpnProtocol())) {
                    alpnEntryList.add(new AlpnEntry(chooser.getConfig().getDefaultSelectedAlpnProtocol()));
                    LOGGER.debug("ALPN selected protocol:" + chooser.getConfig().getDefaultSelectedAlpnProtocol());
                } else if (chooser.getProposedAlpnProtocols().size() > 0) {
                    alpnEntryList.add(new AlpnEntry(chooser.getProposedAlpnProtocols().get(0)));
                    LOGGER
                        .debug("Default ALPN selected protocol is not supported by peer. Respecting client protocols.");
                    LOGGER.debug("ALPN selected protocol:" + chooser.getProposedAlpnProtocols().get(0));
                } else {
                    alpnEntryList.add(new AlpnEntry(chooser.getConfig().getDefaultSelectedAlpnProtocol()));
                    LOGGER.debug("Cannot choose protocol the client supported. Enforcing server choice");
                }
            }
        }
        msg.setAlpnEntryList(alpnEntryList);
        setEntryListBytes(alpnEntryList);
        LOGGER.debug("Prepared the ALPN Extension with announced protocols "
            + ArrayConverter.bytesToHexString(msg.getProposedAlpnProtocols()));
        msg.setProposedAlpnProtocolsLength(msg.getProposedAlpnProtocols().getValue().length);
        LOGGER.debug("Prepared the ALPN Extension with announced protocols length "
            + msg.getProposedAlpnProtocolsLength().getValue());
    }

    private void setEntryListBytes(List<AlpnEntry> alpnEntryList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AlpnEntry entry : alpnEntryList) {
            AlpnEntryPreparator preparator = new AlpnEntryPreparator(chooser, entry);
            preparator.prepare();
            AlpnEntrySerializer serializer = new AlpnEntrySerializer(entry);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                LOGGER.warn("Could not serialize AlpnEntry", ex);
            }
        }
        msg.setProposedAlpnProtocols(stream.toByteArray());
    }
}
