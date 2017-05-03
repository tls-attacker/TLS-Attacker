/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateMessagePreparator extends HandshakeMessagePreparator<CertificateMessage> {

    private final CertificateMessage msg;

    public CertificateMessagePreparator(TlsContext context, CertificateMessage msg) {
        super(context, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        Certificate cert = chooseCert();
        byte[] encodedCert = encodeCert(cert);
        msg.setX509CertificateBytes(encodedCert);
        msg.setCertificatesLength(msg.getX509CertificateBytes().getValue().length);
        if (context.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            prepareExtensions();
            prepareExtensionLength();
        }
    }

    private Certificate chooseCert() {
        Certificate cert = context.getConfig().getOurCertificate();
        if (cert == null) {
            throw new PreparationException("Cannot prepare CertificateMessage since no certificate is specified for "
                    + context.getTalkingConnectionEnd().name());
        } else {
            return cert;
        }
    }

    private byte[] encodeCert(Certificate cert) {
        ByteArrayOutputStream certByteStream = new ByteArrayOutputStream();
        try {
            cert.encode(certByteStream);
            // the encoded cert is actually Length + Bytes so we strap the
            // length
            return Arrays.copyOfRange(certByteStream.toByteArray(), HandshakeByteLength.CERTIFICATES_LENGTH,
                    certByteStream.toByteArray().length);
        } catch (IOException ex) {
            throw new PreparationException(
                    "Cannot prepare CertificateMessage. An exception Occured while encoding the Certificates", ex);
        }

    }
}
