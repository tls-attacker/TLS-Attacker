/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionHandler extends ExtensionHandler<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrtpExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(SrtpExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientSupportedSrtpProtectionProfiles(
                    SrtpProtectionProfile.getProfilesAsArrayList(
                            message.getSrtpProtectionProfiles().getValue()));
            LOGGER.debug(
                    "Adjusted the TLS context secure realtime transport protocol protection profiles to {}",
                    message.getSrtpProtectionProfiles());
            tlsContext.setSecureRealTimeProtocolMasterKeyIdentifier(
                    message.getSrtpMki().getValue());
            LOGGER.debug(
                    "Adjusted the TLS context secure realtime transport protocol master key identifier to {}",
                    message.getSrtpMki());
        } else {
            tlsContext.setSelectedSrtpProtectionProfile(
                    SrtpProtectionProfile.getProfileByType(
                            message.getSrtpProtectionProfiles().getValue()));
            LOGGER.debug(
                    "Server selected the SRTP protection profile: {}",
                    tlsContext.getSelectedSrtpProtectionProfile().name());
        }
    }
}
