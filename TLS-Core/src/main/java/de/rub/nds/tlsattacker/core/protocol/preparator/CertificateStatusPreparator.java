/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusPreparator extends HandshakeMessagePreparator<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final CertificateStatusMessage msg;

    private static final int TYPE_OCSP = 1;
    private static final int TYPE_OCSP_MULTI = 2;

    public CertificateStatusPreparator(Chooser chooser, CertificateStatusMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateStatusMessage");
        LOGGER.debug("Note: This is not properly implemented yet. Will use hardcoded message with empty content.");
        // Dummy message, we can't create an own StatusMessage yet.
        prepareCertificateStatusType();
        prepareOcspResponseLength();
        prepareOcspResponseBytes();
    }

    private void prepareCertificateStatusType() {
        msg.setCertificateStatusType(TYPE_OCSP); // 1: OCSP 2: OCSP_multi
        LOGGER.debug("CertificateStatusType: " + msg.getCertificateStatusType().getValue());
    }

    private void prepareOcspResponseLength() {
        msg.setOcspResponseLength(0);
        LOGGER.debug("OCSPResponseLength: " + msg.getOcspResponseLength());
    }

    private void prepareOcspResponseBytes() {
        msg.setOcspResponseBytes(new byte[0]);
        LOGGER.debug("OCSPResponseBytes: " + ArrayConverter.bytesToHexString(msg.getOcspResponseBytes()));
    }
}
