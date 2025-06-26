/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.cert;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateEntryPreparator extends Preparator<CertificateEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateEntry entry;

    public CertificateEntryPreparator(Chooser chooser, CertificateEntry entry) {
        super(chooser, entry);
        this.entry = entry;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing CertificateEntry");
        prepareCertificateBytes(entry);
        prepareCertificateLength(entry);
        if (entry.getExtensionList() != null) {
            prepareExtensions(entry);
            prepareExtensionLength(entry);
        } else {
            entry.setExtensionsLength(0);
        }
    }

    private void prepareCertificateBytes(CertificateEntry entry) {
        if (entry.getX509certificate() == null && entry.getX509CerticiateConfig() != null) {
            entry.setCertificateBytes(entry.getX509CerticiateConfig());
        } else if (entry.getX509certificate() != null) {
            entry.setCertificateBytes(entry.getX509certificate().getSerializer(null).serialize());
        } else {
            LOGGER.warn("Unsure how to encode entry. Using new byte[0]");
            entry.setCertificateBytes(new byte[0]);
        }

        LOGGER.debug(
                "Certificate: {}",
                DataConverter.bytesToHexString(entry.getCertificateBytes().getValue()));
    }

    private void prepareCertificateLength(CertificateEntry entry) {
        entry.setCertificateLength(entry.getCertificateBytes().getValue().length);
        LOGGER.debug("CertificateLength: {}", entry.getCertificateLength().getValue());
    }

    private void prepareExtensions(CertificateEntry entry) {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        if (entry.getExtensionList() != null) {
            for (ExtensionMessage extensionMessage : entry.getExtensionList()) {
                extensionMessage.getPreparator(chooser.getContext()).prepare();
                stream.write(extensionMessage.getExtensionBytes().getValue());
            }
            entry.setExtensionBytes(stream.toByteArray());
        }
        LOGGER.debug(
                "ExtensionBytes: {}",
                DataConverter.bytesToHexString(entry.getExtensionBytes().getValue()));
    }

    private void prepareExtensionLength(CertificateEntry entry) {
        entry.setExtensionsLength(entry.getExtensionBytes().getValue().length);
        LOGGER.debug("ExtensionLength: {}", entry.getExtensionsLength().getValue());
    }
}
