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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.alpn.AlpnEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.alpn.AlpnEntrySerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AlpnEntry entry : msg.getAlpnEntryList()) {
            AlpnEntryPreparator preparator = new AlpnEntryPreparator(chooser, entry);
            preparator.prepare();
            AlpnEntrySerializer serializer = new AlpnEntrySerializer(entry);
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                LOGGER.warn("Could not serialize AlpnEntry");
            }
        }
        msg.setAlpnAnnouncedProtocols(stream.toByteArray());
        LOGGER.debug("Prepared the ALPN Extension with announced protocols "
                + ArrayConverter.bytesToHexString(msg.getAlpnAnnouncedProtocols()));
        msg.setAlpnExtensionLength(msg.getAlpnAnnouncedProtocols().getValue().length);
        LOGGER.debug("Prepared the ALPN Extension with announced protocols length "
                + msg.getAlpnExtensionLength().getValue());
    }
}
