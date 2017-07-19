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
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificateMessagePreparator extends HandshakeMessagePreparator<CertificateMessage> {

    private final CertificateMessage msg;

    public CertificateMessagePreparator(TlsContext context, CertificateMessage msg) {
        super(context, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateMessage");
        if (context.getSelectedProtocolVersion().isTLS13()) {
            prepareRequestContext(msg);
            prepareRequestContextLength(msg);
        }
        prepareCertificateListBytes(msg);
        msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
    }

    private void prepareCertificateListBytes(CertificateMessage msg) {
        if (context.getSelectedProtocolVersion().isTLS13()) {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (CertificatePair pair : msg.getCertificatesList()) {
                CertificatePairPreparator preparator = new CertificatePairPreparator(context, pair);
                preparator.prepare();
                CertificatePairSerializer serializer = new CertificatePairSerializer(pair);
                try {
                    stream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write byte[] from CertificatePair", ex);
                }
            }
            msg.setCertificatesListBytes(stream.toByteArray());
        } else {
            Certificate cert = chooseCert();
            byte[] encodedCert = encodeCert(cert);
            msg.setCertificatesListBytes(encodedCert);
        }
        LOGGER.debug("CertificatesListBytes: "
                + ArrayConverter.bytesToHexString(msg.getCertificatesListBytes().getValue()));
    }

    private void prepareRequestContext(CertificateMessage msg) {
        if (context.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
            msg.setRequestContext(context.getCertificateRequestContext());
        } else {
            msg.setRequestContext(new byte[0]);
        }
        LOGGER.debug("RequestContext: " + ArrayConverter.bytesToHexString(msg.getRequestContext().getValue()));
    }

    private void prepareRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(msg.getRequestContext().getValue().length);
        LOGGER.debug("RequestContextLength: " + msg.getRequestContextLength().getValue());
    }

    private Certificate chooseCert() {
        Certificate cert = context.getConfig().getOurCertificate();
        if (cert == null) {
            throw new PreparationException("Cannot prepare CertificateMessage since no certificate is specified for "
                    + context.getTalkingConnectionEndType().name());
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
