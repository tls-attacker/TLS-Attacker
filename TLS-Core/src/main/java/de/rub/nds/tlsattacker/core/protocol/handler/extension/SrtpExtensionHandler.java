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
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionHandler extends ExtensionHandler<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrtpExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(SrtpExtensionMessage message) {
        context.setSecureRealTimeTransportProtocolProtectionProfiles(
            SrtpProtectionProfiles.getProfilesAsArrayList(message.getSrtpProtectionProfiles().getValue()));
        LOGGER.debug("Adjusted the TLS context secure realtime transport protocol protection profiles to "
            + ArrayConverter.bytesToHexString(message.getSrtpProtectionProfiles()));
        context.setSecureRealTimeProtocolMasterKeyIdentifier(message.getSrtpMki().getValue());
        LOGGER.debug("Adjusted the TLS context secure realtime transport protocol master key identifier to "
            + ArrayConverter.bytesToHexString(message.getSrtpMki()));
    }
}
