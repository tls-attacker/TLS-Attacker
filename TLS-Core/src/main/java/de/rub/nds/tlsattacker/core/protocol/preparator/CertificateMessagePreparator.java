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
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificatePairPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateMessagePreparator extends HandshakeMessagePreparator<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateMessage msg;

    public CertificateMessagePreparator(Chooser chooser, CertificateMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateMessage");
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            prepareRequestContext(msg);
            prepareRequestContextLength(msg);
        }
        prepareCertificateListBytes(msg);
    }

    private CertificateType selectTypeInternally() {
        if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            return chooser.getSelectedServerCertificateType();
        } else {
            return chooser.getSelectedClientCertificateType();
        }
    }

    private void prepareCertificateListBytes(CertificateMessage msg) {
        switch (selectTypeInternally()) {
            case OPEN_PGP:
                throw new UnsupportedOperationException("We do not support OpenPGP keys");
            case RAW_PUBLIC_KEY:
                LOGGER.debug("Adjusting context for RAW PUBLIC KEY ceritifate message");
                try {
                    // We currently only support this extension only very
                    // limited. Only secp256r1 is supported.
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    ASN1OutputStream asn1OutputStream = new ASN1OutputStream(byteArrayOutputStream);
                    Point ecPointToEncode;
                    if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
                        ecPointToEncode = chooser.getClientEcPublicKey();
                    } else {
                        ecPointToEncode = chooser.getServerEcPublicKey();
                    }
                    asn1OutputStream.writeObject(new DLSequence(new ASN1Encodable[] {
                            new DLSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("1.2.840.10045.2.1"),
                                    new ASN1ObjectIdentifier("1.2.840.10045.3.1.7") }),
                            new DERBitString(PointFormatter.formatToByteArray(ecPointToEncode,
                                    ECPointFormat.UNCOMPRESSED)) }));
                    asn1OutputStream.flush();
                    asn1OutputStream.close();
                    msg.setCertificatesListBytes(byteArrayOutputStream.toByteArray());
                    msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);

                    byteArrayOutputStream.close();
                } catch (Exception E) {
                    LOGGER.warn("Could write RAW PublicKey. Not writing anything", E);
                    msg.setCertificatesListBytes(new byte[0]);
                    msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
                }
                break;

            case X509:
                List<CertificatePair> pairList = msg.getCertificatesList();
                if (pairList == null) {
                    CertificateKeyPair selectedCertificateKeyPair;
                    if (chooser.getConfig().isAutoSelectCertificate()) {
                        selectedCertificateKeyPair = CertificateByteChooser.getInstance().chooseCertificateKeyPair(
                                chooser);
                    } else {
                        selectedCertificateKeyPair = chooser.getConfig().getDefaultExplicitCertificateKeyPair();
                    }
                    msg.setCertificateKeyPair(selectedCertificateKeyPair);
                    byte[] certBytes = selectedCertificateKeyPair.getCertificateBytes();
                    if (certBytes.length >= 3 && selectedCertificateKeyPair.isCertificateParseable()) {
                        pairList = new LinkedList<>();
                        try {
                            Certificate cert = Certificate.parse(new ByteArrayInputStream(certBytes));
                            for (org.bouncycastle.asn1.x509.Certificate subCert : cert.getCertificateList()) {
                                pairList.add(new CertificatePair(subCert.getEncoded()));
                            }
                            msg.setCertificatesList(pairList);
                            prepareFromPairList(msg);
                        } catch (IOException ex) {
                            throw new PreparationException(
                                    "Could not parse a parseable certificate, this should never happen", ex);
                        }

                    } else {
                        msg.setCertificatesListBytes(certBytes);
                        msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
                    }
                } else {
                    prepareFromPairList(msg);
                }

                LOGGER.debug("CertificatesListBytes: "
                        + ArrayConverter.bytesToHexString(msg.getCertificatesListBytes().getValue()));
                break;
            default:
                throw new UnsupportedOperationException("Unsupported CertificateType");
        }

    }

    private void prepareFromPairList(CertificateMessage msg) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CertificatePair pair : msg.getCertificatesList()) {
            CertificatePairPreparator preparator = new CertificatePairPreparator(chooser, pair);
            preparator.prepare();
            CertificatePairSerializer serializer = new CertificatePairSerializer(pair,
                    chooser.getSelectedProtocolVersion());
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from CertificatePair", ex);
            }
        }
        msg.setCertificatesListBytes(stream.toByteArray());
        msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
    }

    private void prepareRequestContext(CertificateMessage msg) {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            msg.setRequestContext(chooser.getCertificateRequestContext());
        } else {
            msg.setRequestContext(new byte[0]);
        }
        LOGGER.debug("RequestContext: " + ArrayConverter.bytesToHexString(msg.getRequestContext().getValue()));
    }

    private void prepareRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(msg.getRequestContext().getValue().length);
        LOGGER.debug("RequestContextLength: " + msg.getRequestContextLength().getValue());
        byte[] encodedCert = CertificateByteChooser.getInstance().chooseCertificateKeyPair(chooser)
                .getCertificateBytes();
        msg.setCertificatesListBytes(encodedCert);
        msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
    }
}
