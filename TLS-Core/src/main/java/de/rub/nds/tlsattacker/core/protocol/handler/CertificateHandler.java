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
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
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

public class CertificateHandler extends HandshakeMessageHandler<CertificateMessage> {

    public CertificateHandler(TlsContext tlsContext) {
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
            if (cert != null) {
                adjustPublicKeyParameters(cert);
            }
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
                tlsContext.setRsaModulus(CertificateUtils.extractRSAModulus(cert));
                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                    tlsContext.setClientRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                    tlsContext.setClientRSAPrivateKey(tlsContext.getConfig().getDefaultClientRSAPrivateKey());
                } else {
                    tlsContext.setServerRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                    tlsContext.setServerRSAPrivateKey(tlsContext.getConfig().getDefaultServerRSAPrivateKey());
                }
            } else {
                LOGGER.warn("Could not adjust Certificate publicKey");
            }
        } catch (IOException | IllegalArgumentException E) {
            throw new AdjustmentException("Could not adjust PublicKey Information from Certificate", E);
        }
    }

    private void adjustDHParameters(DHPublicKeyParameters dhPublicKeyParameters) {
        tlsContext.setDhGenerator(dhPublicKeyParameters.getParameters().getG());
        tlsContext.setDhModulus(dhPublicKeyParameters.getParameters().getP());
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientDhPublicKey(dhPublicKeyParameters.getY());
        } else {
            tlsContext.setServerDhPublicKey(dhPublicKeyParameters.getY());
        }
    }

    private void adjustECParameters(ECPublicKeyParameters ecPublicKeyParameters) {
        tlsContext.setSelectedCurve(CurveNameRetriever.getNamedCuveFromECCurve(ecPublicKeyParameters.getParameters()
                .getCurve()));
        CustomECPoint publicKey = new CustomECPoint(ecPublicKeyParameters.getQ().getRawXCoord().toBigInteger(),
                ecPublicKeyParameters.getQ().getRawYCoord().toBigInteger());
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientEcPublicKey(publicKey);
        } else {
            tlsContext.setServerEcPublicKey(publicKey);
        }
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException | IllegalArgumentException | ClassCastException E) {
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
                        ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                                extension.getExtensionTypeConstant(), HandshakeMessageType.CERTIFICATE);
                        handler.adjustTLSContext(extension);
                    }
                }
            }
        }
    }
}
