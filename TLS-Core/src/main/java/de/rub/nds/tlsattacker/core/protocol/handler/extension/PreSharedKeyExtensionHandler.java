/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC draft-ietf-tls-tls13-21 */
public class PreSharedKeyExtensionHandler extends ExtensionHandler<PreSharedKeyExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PreSharedKeyExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(PreSharedKeyExtensionMessage message) {
        LOGGER.debug("Adjusting TLS Context for PSK Key Extension Message");
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            if (message.getSelectedIdentity() != null) {
                adjustPsk(message);
            } else {
                if (tlsContext.getChooser().getPskSets().size() > 0) {
                    tlsContext.setEarlyDataPSKIdentity(
                            tlsContext.getChooser().getPskSets().get(0).getPreSharedKeyIdentity());
                    tlsContext.setEarlyDataCipherSuite(
                            tlsContext.getChooser().getPskSets().get(0).getCipherSuite());
                } else {
                    LOGGER.warn("Could not adjust EarlyData Identity and Cipher suite");
                }
            }
        }
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
                && message.getIdentities() != null
                && message.getIdentities().size() > 0) {
            selectPsk(message);
            if (tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                selectEarlyDataPsk(message);
            }
        }
    }

    private void adjustPsk(PreSharedKeyExtensionMessage message) {
        if (message.getSelectedIdentity() != null
                && message.getSelectedIdentity().getValue() != null
                && message.getSelectedIdentity().getValue()
                        < tlsContext.getChooser().getPskSets().size()) {
            LOGGER.debug("Setting PSK as chosen by server");
            tlsContext.setPsk(
                    tlsContext
                            .getChooser()
                            .getPskSets()
                            .get(message.getSelectedIdentity().getValue())
                            .getPreSharedKey());
            tlsContext.setSelectedIdentityIndex(message.getSelectedIdentity().getValue());
        } else {
            LOGGER.warn("The server's chosen PSK identity is unknown - no psk set");
        }
    }

    private void selectPsk(PreSharedKeyExtensionMessage message) {
        int pskIdentityIndex = 0;
        List<PskSet> pskSets = tlsContext.getChooser().getPskSets();
        if (message.getIdentities() != null) {
            for (PSKIdentity pskIdentity : message.getIdentities()) {
                for (int x = 0; x < pskSets.size(); x++) {
                    if (Arrays.equals(
                            pskSets.get(x).getPreSharedKeyIdentity(),
                            pskIdentity.getIdentity().getValue())) {
                        LOGGER.debug(
                                "Selected PSK identity: {}",
                                pskSets.get(x).getPreSharedKeyIdentity());
                        tlsContext.setPsk(pskSets.get(x).getPreSharedKey());
                        tlsContext.setEarlyDataCipherSuite(pskSets.get(x).getCipherSuite());
                        tlsContext.setSelectedIdentityIndex(pskIdentityIndex);
                        return;
                    }
                }
                pskIdentityIndex++;
            }
        }
        LOGGER.warn("No matching PSK identity provided by client - no PSK was set");
    }

    private void selectEarlyDataPsk(PreSharedKeyExtensionMessage message) {

        LOGGER.debug(
                "Calculating early traffic secret using transcript: {}",
                tlsContext.getDigest().getRawBytes());

        List<PskSet> pskSets = tlsContext.getChooser().getPskSets();
        for (int x = 0; x < pskSets.size(); x++) {
            if (Arrays.equals(
                    pskSets.get(x).getPreSharedKeyIdentity(),
                    message.getIdentities().get(0).getIdentity().getValue())) {
                tlsContext.setEarlyDataPsk(pskSets.get(x).getPreSharedKey());
                tlsContext.setEarlyDataCipherSuite(pskSets.get(x).getCipherSuite());
                LOGGER.debug("EarlyData PSK: {}", pskSets.get(x).getPreSharedKey());
                break;
            }
        }
        if (tlsContext.getEarlyDataPsk() == null) {
            LOGGER.warn("Server is missing the EarlyData PSK - decryption will fail");
        }
    }
}
