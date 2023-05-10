/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionPreparator extends ExtensionPreparator<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SrtpExtensionMessage msg;

    public SrtpExtensionPreparator(
            Chooser chooser,
            SrtpExtensionMessage message,
            ExtensionSerializer<SrtpExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        try {
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
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
                    ArrayConverter.bytesToHexString(msg.getSrtpProtectionProfiles()));
            msg.setSrtpProtectionProfilesLength(msg.getSrtpProtectionProfiles().getValue().length);
            LOGGER.debug(
                    "ProtectionProfile Length: {} ",
                    msg.getSrtpProtectionProfilesLength().getValue());
            msg.setSrtpMki(
                    chooser.getConfig().getSecureRealTimeTransportProtocolMasterKeyIdentifier());
            LOGGER.debug("MKI: {}", ArrayConverter.bytesToHexString(msg.getSrtpMki()));
            msg.setSrtpMkiLength(msg.getSrtpMki().getValue().length);
            LOGGER.debug("MKI Length: {}", msg.getSrtpMkiLength().getValue());
        } catch (IOException E) {
            LOGGER.error("Could not write to local stream", E);
        }
    }
}
