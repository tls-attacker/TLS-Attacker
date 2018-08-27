/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.cert;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairPreparator extends Preparator<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificatePair pair;

    public CertificatePairPreparator(Chooser chooser, CertificatePair pair) {
        super(chooser, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing CertificatePair");
        prepareCertificate(pair);
        prepareCertificateLength(pair);
        if (pair.getExtensionsConfig() != null) {
            prepareExtensions(pair);
            prepareExtensionLength(pair);
        } else {
            pair.setExtensionsLength(0);
        }
    }

    private void prepareCertificate(CertificatePair pair) {
        pair.setCertificate(pair.getCertificateConfig());
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(pair.getCertificate().getValue()));
    }

    private void prepareCertificateLength(CertificatePair pair) {
        pair.setCertificateLength(pair.getCertificate().getValue().length);
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    private void prepareExtensions(CertificatePair pair) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (pair.getExtensionsConfig() != null) {
            for (ExtensionMessage extensionMessage : pair.getExtensionsConfig()) {
                HandshakeMessageType handshakeMessageType = HandshakeMessageType.CERTIFICATE;
                if (extensionMessage instanceof HRRKeyShareExtensionMessage) {
                    handshakeMessageType = HandshakeMessageType.HELLO_RETRY_REQUEST;
                }
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(chooser.getContext(),
                        extensionMessage.getExtensionTypeConstant(), handshakeMessageType);
                handler.getPreparator(extensionMessage).prepare();
                try {
                    stream.write(extensionMessage.getExtensionBytes().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                }
            }
            pair.setExtensions(stream.toByteArray());
        }
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(pair.getExtensions().getValue()));
    }

    private void prepareExtensionLength(CertificatePair pair) {
        pair.setExtensionsLength(pair.getExtensions().getValue().length);
        LOGGER.debug("ExtensionLength: " + pair.getExtensionsLength().getValue());
    }

}
