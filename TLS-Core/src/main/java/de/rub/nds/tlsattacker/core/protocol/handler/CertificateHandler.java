/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.core.util.CurveNameRetriever;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateHandler extends HandshakeMessageHandler<CertificateMessage> {

    public CertificateHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateMessageParser getParser(byte[] message, int pointer) {
        return new CertificateMessageParser(pointer, message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getLastRecordVersion());
    }

    @Override
    public CertificateMessagePreparator getPreparator(CertificateMessage message) {
        return new CertificateMessagePreparator(new DefaultChooser(tlsContext, tlsContext.getConfig()), message);
    }

    @Override
    public CertificateMessageSerializer getSerializer(CertificateMessage message) {
        return new CertificateMessageSerializer(message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(CertificateMessage message) {
        Certificate cert = parseCertificate(message.getCertificatesLength().getValue(), message
                .getX509CertificateBytes().getValue());
        if (cert != null) {
            adjustPublicKeyParameters(cert);
        }
        if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            LOGGER.debug("Setting ClientCertificate in Context");
            tlsContext.setClientCertificate(cert);
        } else {
            LOGGER.debug("Setting ServerCertificate in Context");
            tlsContext.setServerCertificate(cert);
        }
    }

    private void adjustPublicKeyParameters(Certificate cert) {
        try {
            if (CertificateUtils.hasDHParameters(cert)) {
                DHPublicKeyParameters dhParameters = CertificateUtils.extractDHPublicKeyParameters(cert);
                adjustDHParameters(dhParameters);
            } else if (CertificateUtils.hasECParameters(cert)) {
                ECPublicKeyParameters ecParameters = CertificateUtils.extractECPublicKeyParameters(cert);
                adjustECParameters(ecParameters);
            } else if (CertificateUtils.hasRSAParameters(cert)) {
                tlsContext.setRsaModulus(CertificateUtils.extractRSAModulus(cert));
                if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
                    tlsContext.setClientRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                } else {
                    tlsContext.setServerRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                }
            }
        } catch (IOException E) {
            throw new AdjustmentException("Could not adjust PublicKey Information from Certificate", E);
        }
    }

    private void adjustDHParameters(DHPublicKeyParameters dhPublicKeyParameters) {
        tlsContext.setDhGenerator(dhPublicKeyParameters.getParameters().getG());
        tlsContext.setDhModulus(dhPublicKeyParameters.getParameters().getP());
        if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            tlsContext.setClientDhPublicKey(dhPublicKeyParameters.getY());
        } else {
            tlsContext.setServerDhPublicKey(dhPublicKeyParameters.getY());
        }
    }

    private void adjustECParameters(ECPublicKeyParameters ecPublicKeyParameters) {
        tlsContext.setSelectedCurve(CurveNameRetriever.getNamedCuveFromECCurve(ecPublicKeyParameters.getParameters()
                .getCurve()));
        if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            tlsContext.setClientEcPublicKey(ecPublicKeyParameters.getQ());
        } else {
            tlsContext.setServerEcPublicKey(ecPublicKeyParameters.getQ());
        }
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException E) {
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false));
            return null;
        }
    }
}
