/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.core.util.CurveNameRetriever;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;

public class CertificateMessageHandler extends HandshakeMessageHandler<CertificateMessage> {

    public CertificateMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateMessageParser getParser(byte[] message, int pointer) {
        return new CertificateMessageParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public CertificateMessagePreparator getPreparator(CertificateMessage message) {
        return new CertificateMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public CertificateMessageSerializer getSerializer(CertificateMessage message) {
        return new CertificateMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(CertificateMessage message) {
        Certificate cert;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            int certificatesLength = 0;
            try {
                for (CertificatePair pair : message.getCertificatesList()) {
                    stream.write(ArrayConverter.intToBytes(pair.getCertificateLength().getValue(),
                            HandshakeByteLength.CERTIFICATE_LENGTH));
                    stream.write(pair.getCertificate().getValue());
                    certificatesLength += pair.getCertificateLength().getValue()
                            + HandshakeByteLength.CERTIFICATE_LENGTH;
                }
            } catch (IOException ex) {
                throw new AdjustmentException("Could not concatenate certificates bytes", ex);
            }
            cert = parseCertificate(certificatesLength, stream.toByteArray());
        } else {
            cert = parseCertificate(message.getCertificatesListLength().getValue(), message.getCertificatesListBytes()
                    .getValue());
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            LOGGER.debug("Setting ClientCertificate in Context");
            tlsContext.setClientCertificate(cert);
        } else {
            LOGGER.debug("Setting ServerCertificate in Context");
            tlsContext.setServerCertificate(cert);
        }
        if (cert != null) {
            adjustPublicKeyParameters(cert);
        }
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            adjustExtensions(message);
        }
    }

    private void adjustPublicKeyParameters(Certificate cert) {
        try {
            if (CertificateUtils.hasDHParameters(cert)) {
                LOGGER.debug("Adjusting DH PublicKey");
                DHPublicKeyParameters dhParameters = CertificateUtils.extractDHPublicKeyParameters(cert);
                adjustDHParameters(dhParameters);
            } else if (CertificateUtils.hasECParameters(cert)) {
                LOGGER.debug("Adjusting EC PublicKey");
                ECPublicKeyParameters ecParameters = CertificateUtils.extractECPublicKeyParameters(cert);
                adjustECParameters(ecParameters);
            } else if (CertificateUtils.hasRSAParameters(cert)) {
                LOGGER.debug("Adjusting RSA PublicKey");
                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                    tlsContext.setClientRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                    tlsContext.setClientRSAPrivateKey(tlsContext.getConfig().getDefaultClientRSAPrivateKey());
                    tlsContext.setClientRsaModulus(CertificateUtils.extractRSAModulus(cert));
                } else {
                    tlsContext.setServerRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                    tlsContext.setServerRSAPrivateKey(tlsContext.getConfig().getDefaultServerRSAPrivateKey());
                    tlsContext.setServerRsaModulus(CertificateUtils.extractRSAModulus(cert));
                }
            } else if (CertificateUtils.hasGost01EcParameters(cert)) {
                adjustGost01Parameters(CertificateUtils.extract01PublicKey(cert));
            } else if (CertificateUtils.hasGost12EcParameters(cert)) {
                adjustGost12Parameters(CertificateUtils.extract12PublicKey(cert));
            } else {
                LOGGER.warn("Could not adjust Certificate publicKey. Ceritifcate does not seem to Contain a PublicKey");
            }
        } catch (IOException | IllegalArgumentException E) {
            LOGGER.debug(E);
            throw new AdjustmentException("Could not adjust PublicKey Information from Certificate", E);
        }
    }

    private void adjustGost01Parameters(BCECGOST3410PublicKey publicKey) {
        LOGGER.debug("Adjusting GOST 2001 ECPublicKey");
        CustomECPoint ecPoint = toCustomECPoint(publicKey.getQ());
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientGost01Curve(((ECNamedCurveSpec) publicKey.getParams()).getName());
            tlsContext.setClientGostEc01PublicKey(ecPoint);
        } else {
            tlsContext.setServerGost01Curve(((ECNamedCurveSpec) publicKey.getParams()).getName());
            tlsContext.setServerGostEc01PublicKey(ecPoint);
        }
    }

    private void adjustGost12Parameters(BCECGOST3410_2012PublicKey publicKey) {
        LOGGER.debug("Adjusting GOST 2012 ECPublicKey");
        CustomECPoint ecPoint = toCustomECPoint(publicKey.getQ());
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientGost12Curve(((ECNamedCurveSpec) publicKey.getParams()).getName());
            tlsContext.setClientGostEc12PublicKey(ecPoint);
        } else {
            tlsContext.setServerGost12Curve(((ECNamedCurveSpec) publicKey.getParams()).getName());

            tlsContext.setServerGostEc12PublicKey(ecPoint);
        }
    }

    private CustomECPoint toCustomECPoint(ECPoint q) {
        return new CustomECPoint(q.getRawXCoord().toBigInteger(), q.getRawYCoord().toBigInteger());
    }

    private void adjustDHParameters(DHPublicKeyParameters dhPublicKeyParameters) {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientDhGenerator(dhPublicKeyParameters.getParameters().getG());
            tlsContext.setClientDhModulus(dhPublicKeyParameters.getParameters().getP());
            tlsContext.setClientDhPublicKey(dhPublicKeyParameters.getY());
        } else {
            tlsContext.setServerDhGenerator(dhPublicKeyParameters.getParameters().getG());
            tlsContext.setServerDhModulus(dhPublicKeyParameters.getParameters().getP());
            tlsContext.setServerDhPublicKey(dhPublicKeyParameters.getY());
        }
    }

    private void adjustECParameters(ECPublicKeyParameters ecPublicKeyParameters) {
        CustomECPoint publicKey = toCustomECPoint(ecPublicKeyParameters.getQ());
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientEcPublicKey(publicKey);
            tlsContext.setEcCertificateCurve(CurveNameRetriever.getNamedCuveFromECCurve(ecPublicKeyParameters
                    .getParameters().getCurve()));
        } else {
            tlsContext.setServerEcPublicKey(publicKey);
            tlsContext.setSelectedGroup(CurveNameRetriever.getNamedCuveFromECCurve(ecPublicKeyParameters
                    .getParameters().getCurve()));
        }
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (Exception E) {
            // This could really be anything. From classCast exception to
            // Arrayindexoutofbounds
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false));
            LOGGER.debug(E);
            return null;
        }
    }

    private void adjustExtensions(CertificateMessage message) {
        if (message.getCertificatesListAsEntry() != null) {
            for (CertificateEntry entry : message.getCertificatesListAsEntry()) {
                if (entry.getExtensions() != null) {
                    for (ExtensionMessage extension : entry.getExtensions()) {
                        HandshakeMessageType handshakeMessageType = HandshakeMessageType.CERTIFICATE;
                        if (extension instanceof HRRKeyShareExtensionMessage) { // TODO
                                                                                // fix
                                                                                // design
                                                                                // flaw
                            handshakeMessageType = HandshakeMessageType.HELLO_RETRY_REQUEST;
                        }
                        ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                                extension.getExtensionTypeConstant(), handshakeMessageType);
                        handler.adjustTLSContext(extension);
                    }
                }
            }
        }
    }
}
