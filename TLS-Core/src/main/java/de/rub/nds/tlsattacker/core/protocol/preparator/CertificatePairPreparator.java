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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.crypto.tls.Certificate;

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
        pair.setCertificate(encodeCert(pair.getCertificateConfig()));
        pair.setCertificateLength(pair.getCertificate().getValue().length);
        prepareExtensions();
        prepareExtensionLength();
    }
  
    private void prepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (pair.getExtensionsConfig() != null) {
            for (ExtensionMessage extensionMessage : pair.getExtensionsConfig()) {
                ExtensionHandler handler = extensionMessage.getHandler(context);
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

    private void prepareExtensionLength() {
        pair.setExtensionsLength(pair.getExtensions().getValue().length);
        LOGGER.debug("ExtensionLength: " + pair.getExtensionsLength().getValue());
    }
    
    private byte[] encodeCert(Certificate cert) {
        ByteArrayOutputStream certByteStream = new ByteArrayOutputStream();
        try {
            cert.encode(certByteStream);
            return Arrays.copyOfRange(certByteStream.toByteArray(), HandshakeByteLength.CERTIFICATES_LENGTH
                    + HandshakeByteLength.CERTIFICATE_LENGTH, certByteStream.toByteArray().length);
        } catch (IOException ex) {
            throw new PreparationException(
                    "Cannot prepare CertificateMessage. An exception Occured while encoding the Certificates", ex);
        }

    }
}