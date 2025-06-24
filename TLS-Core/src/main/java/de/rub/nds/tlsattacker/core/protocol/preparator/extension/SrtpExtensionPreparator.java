/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionPreparator extends ExtensionPreparator<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SrtpExtensionMessage msg;

    public SrtpExtensionPreparator(Chooser chooser, SrtpExtensionMessage message) {
        super(chooser, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        SilentByteArrayOutputStream byteStream = new SilentByteArrayOutputStream();
        if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
            for (SrtpProtectionProfile profile :
                    chooser.getConfig().getClientSupportedSrtpProtectionProfiles()) {
                byteStream.write(profile.getByteValue());
            }
        } else {
            byteStream.write(chooser.getSelectedSrtpProtectionProfile().getByteValue());
        }
        msg.setSrtpProtectionProfiles(byteStream.toByteArray());
        LOGGER.debug(
                "ProtectionProfiles: {}",
                DataConverter.bytesToHexString(msg.getSrtpProtectionProfiles()));
        msg.setSrtpProtectionProfilesLength(msg.getSrtpProtectionProfiles().getValue().length);
        LOGGER.debug(
                "ProtectionProfile Length: {} ", msg.getSrtpProtectionProfilesLength().getValue());
        msg.setSrtpMki(chooser.getConfig().getSecureRealTimeTransportProtocolMasterKeyIdentifier());
        LOGGER.debug("MKI: {}", DataConverter.bytesToHexString(msg.getSrtpMki()));
        msg.setSrtpMkiLength(msg.getSrtpMki().getValue().length);
        LOGGER.debug("MKI Length: {}", msg.getSrtpMkiLength().getValue());
    }
}
