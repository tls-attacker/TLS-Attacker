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
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionPreparator extends ExtensionPreparator<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SrtpExtensionMessage msg;

    public SrtpExtensionPreparator(Chooser chooser, SrtpExtensionMessage message,
            ExtensionSerializer<SrtpExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        for (SrtpProtectionProfiles profile : chooser.getConfig()
                .getSecureRealTimeTransportProtocolProtectionProfiles()) {
            byteStream.write(profile.getMinor());
            byteStream.write(profile.getMajor());
        }
        msg.setSrtpProtectionProfiles(byteStream.toByteArray());
        LOGGER.debug("Prepared the SRTP extension with protection profiles "
                + ArrayConverter.bytesToHexString(msg.getSrtpProtectionProfiles()));
        msg.setSrtpProtectionProfilesLength(msg.getSrtpProtectionProfiles().getValue().length);
        LOGGER.debug("Prepared the SRTP extension with protection profiles length "
                + msg.getSrtpProtectionProfilesLength().getValue());

        if (chooser.getConfig().getSecureRealTimeTransportProtocolMasterKeyIdentifier().length != 0) {
            msg.setSrtpMki(chooser.getConfig().getSecureRealTimeTransportProtocolMasterKeyIdentifier());
            LOGGER.debug("Prepared the SRTP extension with MKI " + ArrayConverter.bytesToHexString(msg.getSrtpMki()));
            msg.setSrtpMkiLength(msg.getSrtpMki().getValue().length);
            LOGGER.debug("Prepared the SRTP extension with mki length " + msg.getSrtpMkiLength().getValue());
        } else {
            msg.setSrtpMki(chooser.getConfig().getSecureRealTimeTransportProtocolMasterKeyIdentifier());
            msg.setSrtpMkiLength(0);
            LOGGER.debug("Prepared the SRTP extension with no MKI, hence the length is 0");
        }
    }

}
