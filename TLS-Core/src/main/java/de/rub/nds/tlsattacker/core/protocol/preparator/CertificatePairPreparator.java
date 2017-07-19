/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificatePairPreparator extends Preparator<CertificatePair> {

    private final CertificatePair pair;

    public CertificatePairPreparator(TlsContext context, CertificatePair pair) {
        super(context, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing CertificatePair");
        prepareCertificate(pair);
        prepareCertificateLength(pair);
        prepareExtensions(pair);
        prepareExtensionLength(pair);
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
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(context,
                        extensionMessage.getExtensionTypeConstant());
                handler.getPreparator(extensionMessage).prepare();
                try {
                    stream.write(extensionMessage.getExtensionBytes().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                }
            }
        }
        pair.setExtensions(stream.toByteArray());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(pair.getExtensions().getValue()));
    }

    private void prepareExtensionLength(CertificatePair pair) {
        pair.setExtensionsLength(pair.getExtensions().getValue().length);
        LOGGER.debug("ExtensionLength: " + pair.getExtensionsLength().getValue());
    }

}