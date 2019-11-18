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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PreSharedKeyExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PreSharedKeyExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PreSharedKeyExtensionHandler extends ExtensionHandler<PreSharedKeyExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PreSharedKeyExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new PreSharedKeyExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(PreSharedKeyExtensionMessage message) {
        return new PreSharedKeyExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(PreSharedKeyExtensionMessage message) {
        return new PreSharedKeyExtensionSerializer(message, context.getChooser().getConnectionEndType());
    }

    @Override
    public void adjustTLSExtensionContext(PreSharedKeyExtensionMessage message) {
        LOGGER.debug("Adjusting TLS Context for PSK Key Extension Message");
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            if (message.getSelectedIdentity() != null) {
                adjustPsk(message);
            } else {
                if (context.getChooser().getPskSets().size() > 0) {
                    context.setEarlyDataPSKIdentity(context.getChooser().getPskSets().get(0).getPreSharedKeyIdentity());
                    context.setEarlyDataCipherSuite(context.getChooser().getPskSets().get(0).getCipherSuite());
                } else {
                    LOGGER.warn("Could not adjust EarlyData Identity and Ciphersuite");
                }
            }
        }
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER && message.getIdentities() != null
                && message.getIdentities().size() > 0) {
            selectPsk(message);
            if (context.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                selectEarlyDataPsk(message);
            }
        }
    }

    private void adjustPsk(PreSharedKeyExtensionMessage message) {
        if (message.getSelectedIdentity() != null && message.getSelectedIdentity().getValue() != null
                && message.getSelectedIdentity().getValue() < context.getChooser().getPskSets().size()) {
            LOGGER.debug("Setting PSK as chosen by server");
            context.setPsk(context.getChooser().getPskSets().get(message.getSelectedIdentity().getValue())
                    .getPreSharedKey());
            context.setSelectedIdentityIndex(message.getSelectedIdentity().getValue());
        } else {
            LOGGER.warn("The server's chosen PSK identity is unknown - no psk set");
        }
    }

    private void selectPsk(PreSharedKeyExtensionMessage message) {
        int pskIdentityIndex = 0;
        List<PskSet> pskSets = context.getChooser().getPskSets();
        if (message.getIdentities() != null) {
            for (PSKIdentity pskIdentity : message.getIdentities()) {
                for (int x = 0; x < pskSets.size(); x++) {
                    if (Arrays.equals(pskSets.get(x).getPreSharedKeyIdentity(), pskIdentity.getIdentity().getValue())) {
                        LOGGER.debug("Selected PSK identity: "
                                + ArrayConverter.bytesToHexString(pskSets.get(x).getPreSharedKeyIdentity()));
                        context.setPsk(pskSets.get(x).getPreSharedKey());
                        context.setEarlyDataCipherSuite(pskSets.get(x).getCipherSuite());
                        context.setSelectedIdentityIndex(pskIdentityIndex);
                        return;
                    }
                }
                pskIdentityIndex++;
            }
        }
        LOGGER.warn("No matching PSK identity provided by client - no PSK was set");
    }

    private void selectEarlyDataPsk(PreSharedKeyExtensionMessage message) {

        LOGGER.debug("Calculating early traffic secret using transcript: "
                + ArrayConverter.bytesToHexString(context.getDigest().getRawBytes()));

        List<PskSet> pskSets = context.getChooser().getPskSets();
        byte[] earlyDataPsk = null;
        for (int x = 0; x < pskSets.size(); x++) {
            if (Arrays.equals(pskSets.get(x).getPreSharedKeyIdentity(), message.getIdentities().get(0).getIdentity()
                    .getValue())) {
                context.setEarlyDataPsk(pskSets.get(x).getPreSharedKey());
                context.setEarlyDataCipherSuite(pskSets.get(x).getCipherSuite());
                LOGGER.debug("EarlyData PSK: " + ArrayConverter.bytesToHexString(earlyDataPsk));
                break;
            }
        }
        if (earlyDataPsk == null) {
            LOGGER.warn("Server is missing the EarlyData PSK - decryption will fail");
        }
    }

}
