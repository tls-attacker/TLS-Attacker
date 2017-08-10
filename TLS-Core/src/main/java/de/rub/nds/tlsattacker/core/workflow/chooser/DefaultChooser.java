/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class DefaultChooser extends Chooser {

    DefaultChooser(TlsContext context, Config config) {
        super(context, config);
    }

    @Override
    public List<ECPointFormat> getClientSupportedPointFormats() {
        if (context.getClientPointFormatsList() != null) {
            return context.getClientPointFormatsList();
        } else {
            return config.getDefaultClientSupportedPointFormats();
        }
    }

    @Override
    public SignatureAndHashAlgorithm getSelectedSigHashAlgorithm() {
        if (context.getSelectedSignatureAndHashAlgorithm() != null) {
            return context.getSelectedSignatureAndHashAlgorithm();
        } else {
            return config.getDefaultSelectedSignatureAndHashAlgorithm();
        }
    }

    @Override
    public List<NamedCurve> getClientSupportedNamedCurves() {
        if (context.getClientNamedCurvesList() != null) {
            return context.getClientNamedCurvesList();
        } else {
            return config.getDefaultClientNamedCurves();
        }
    }

    @Override
    public List<ECPointFormat> getServerSupportedPointFormats() {
        if (context.getServerPointFormatsList() != null) {
            return context.getServerPointFormatsList();
        } else {
            return config.getDefaultServerSupportedPointFormats();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        if (context.getClientSupportedSignatureAndHashAlgorithms() != null) {
            return context.getClientSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultClientSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public List<SNIEntry> getClientSNIEntryList() {
        if (context.getClientSNIEntryList() != null) {
            return context.getClientSNIEntryList();
        } else {
            return config.getDefaultClientSNIEntryList();
        }
    }

    @Override
    public ProtocolVersion getLastRecordVersion() {
        if (context.getLastRecordVersion() != null) {
            return context.getLastRecordVersion();
        } else {
            return config.getDefaultLastRecordProtocolVersion();
        }
    }

    @Override
    public byte[] getDistinguishedNames() {
        if (context.getDistinguishedNames() != null) {
            return context.getDistinguishedNames();
        } else {
            return config.getDistinguishedNames();
        }
    }

    @Override
    public List<ClientCertificateType> getClientCertificateTypes() {
        if (context.getClientCertificateTypes() != null) {
            return context.getClientCertificateTypes();
        } else {
            return config.getClientCertificateTypes();
        }
    }

    @Override
    public MaxFragmentLength getMaxFragmentLength() {
        if (context.getMaxFragmentLength() != null) {
            return context.getMaxFragmentLength();
        } else {
            return config.getDefaultMaxFragmentLength();
        }
    }

    @Override
    public HeartbeatMode getHeartbeatMode() {
        if (context.getHeartbeatMode() != null) {
            return context.getHeartbeatMode();
        } else {
            return config.getDefaultHeartbeatMode();
        }
    }

    @Override
    public boolean isExtendedMasterSecretExtension() {
        return context.isExtendedMasterSecretExtension();
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressions() {
        if (context.getClientSupportedCompressions() != null) {
            return context.getClientSupportedCompressions();
        } else {
            return config.getDefaultClientSupportedCompressionMethods();
        }
    }

    @Override
    public List<CipherSuite> getClientSupportedCiphersuites() {
        if (context.getClientSupportedCiphersuites() != null) {
            return context.getClientSupportedCiphersuites();
        } else {
            return config.getDefaultClientSupportedCiphersuites();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        if (context.getServerSupportedSignatureAndHashAlgorithms() != null) {
            return context.getServerSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultServerSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getSelectedProtocolVersion() {
        if (context.getSelectedProtocolVersion() != null) {
            return context.getSelectedProtocolVersion();
        } else {
            return config.getDefaultSelectedProtocolVersion();
        }
    }

    @Override
    public ProtocolVersion getHighestClientProtocolVersion() {
        if (context.getHighestClientProtocolVersion() != null) {
            return context.getHighestClientProtocolVersion();
        } else {
            return config.getDefaultHighestClientProtocolVersion();
        }
    }

    @Override
    public ConnectionEndType getTalkingConnectionEnd() {
        return context.getTalkingConnectionEndType();
    }

    @Override
    public byte[] getMasterSecret() {
        if (context.getMasterSecret() != null) {
            return context.getMasterSecret();
        } else {
            return config.getDefaultMasterSecret();
        }
    }

    @Override
    public CipherSuite getSelectedCipherSuite() {
        if (context.getSelectedCipherSuite() != null) {
            return context.getSelectedCipherSuite();
        } else {
            return config.getDefaultSelectedCipherSuite();
        }
    }

    @Override
    public byte[] getPreMasterSecret() {
        if (context.getPreMasterSecret() != null) {
            return context.getPreMasterSecret();
        } else {
            return config.getDefaultPreMasterSecret();
        }
    }

    @Override
    public byte[] getClientRandom() {
        if (context.getClientRandom() != null) {
            return context.getClientRandom();
        } else {
            return config.getDefaultClientRandom();
        }
    }

    @Override
    public byte[] getServerRandom() {
        if (context.getServerRandom() != null) {
            return context.getServerRandom();
        } else {
            return config.getDefaultServerRandom();
        }
    }

    @Override
    public CompressionMethod getSelectedCompressionMethod() {
        if (context.getSelectedCompressionMethod() != null) {
            return context.getSelectedCompressionMethod();
        } else {
            return config.getDefaultSelectedCompressionMethod();
        }
    }

    @Override
    public byte[] getClientSessionId() {
        if (context.getClientSessionId() != null) {
            return context.getClientSessionId();
        } else {
            return config.getDefaultClientSessionId();
        }
    }

    @Override
    public byte[] getServerSessionId() {
        if (context.getServerSessionId() != null) {
            return context.getServerSessionId();
        } else {
            return config.getDefaultServerSessionId();
        }
    }

    @Override
    public byte[] getDtlsCookie() {
        if (context.getDtlsCookie() != null) {
            return context.getDtlsCookie();
        } else {
            return config.getDefaultDtlsCookie();
        }
    }

    @Override
    public TransportHandler getTransportHandler() {
        return context.getTransportHandler();
    }

    @Override
    public PRFAlgorithm getPRFAlgorithm() {
        if (context.getPrfAlgorithm() != null) {
            return context.getPrfAlgorithm();
        } else {
            return config.getDefaultPRFAlgorithm();
        }
    }

    @Override
    public byte[] getSessionTicketTLS() {
        if (context.getSessionTicketTLS() != null) {
            return context.getSessionTicketTLS();
        } else {
            return config.getTLSSessionTicket();
        }
    }

    @Override
    public byte[] getSignedCertificateTimestamp() {
        if (context.getSignedCertificateTimestamp() != null) {
            return context.getSignedCertificateTimestamp();
        } else {
            return config.getDefaultSignedCertificateTimestamp();
        }
    }

    @Override
    public byte[] getRenegotiationInfo() {
        if (context.getRenegotiationInfo() != null) {
            return context.getRenegotiationInfo();
        } else {
            return config.getDefaultRenegotiationInfo();
        }
    }

    @Override
    public TokenBindingVersion getTokenBindingVersion() {
        if (context.getTokenBindingVersion() != null) {
            return context.getTokenBindingVersion();
        } else {
            return config.getDefaultTokenBindingVersion();
        }
    }

    @Override
    public List<TokenBindingKeyParameters> getTokenBindingKeyParameters() {
        if (context.getTokenBindingKeyParameters() != null) {
            return context.getTokenBindingKeyParameters();
        } else {
            return config.getDefaultTokenBindingKeyParameters();
        }
    }

    @Override
    public BigInteger getDhModulus() {
        if (context.getDhModulus() != null) {
            return context.getDhModulus();
        } else {
            return config.getDefaultDhModulus();
        }
    }

    @Override
    public BigInteger getDhGenerator() {
        if (context.getDhGenerator() != null) {
            return context.getDhGenerator();
        } else {
            return config.getDefaultDhGenerator();
        }
    }

    @Override
    public BigInteger getDhServerPrivateKey() {
        if (context.getServerDhPrivateKey() != null) {
            return context.getServerDhPrivateKey();
        } else {
            return config.getDefaultServerDhPrivateKey();
        }
    }

    @Override
    public BigInteger getDhClientPrivateKey() {
        if (context.getClientDhPrivateKey() != null) {
            return context.getClientDhPrivateKey();
        } else {
            return config.getDefaultClientDhPrivateKey();
        }
    }

    @Override
    public BigInteger getDhServerPublicKey() {
        if (context.getServerDhPublicKey() != null) {
            return context.getServerDhPublicKey();
        } else {
            return config.getDefaultServerDhPublicKey();
        }
    }

    @Override
    public BigInteger getDhClientPublicKey() {
        if (context.getClientDhPublicKey() != null) {
            return context.getClientDhPublicKey();
        } else {
            return config.getDefaultClientDhPublicKey();
        }
    }

    @Override
    public BigInteger getServerEcPrivateKey() {
        if (context.getServerEcPrivateKey() != null) {
            return context.getServerEcPrivateKey();
        } else {
            return config.getDefaultServerEcPrivateKey();
        }
    }

    @Override
    public BigInteger getClientEcPrivateKey() {
        if (context.getClientEcPrivateKey() != null) {
            return context.getClientEcPrivateKey();
        } else {
            return config.getDefaultClientEcPrivateKey();
        }
    }

    @Override
    public NamedCurve getSelectedCurve() {
        if (context.getSelectedCurve() != null) {
            return context.getSelectedCurve();
        } else {
            return config.getDefaultSelectedCurve();
        }
    }

    @Override
    public CustomECPoint getClientEcPublicKey() {
        if (context.getClientEcPublicKey() != null) {
            return context.getClientEcPublicKey();
        } else {
            return config.getDefaultClientEcPublicKey();
        }
    }

    @Override
    public CustomECPoint getServerEcPublicKey() {
        if (context.getServerEcPublicKey() != null) {
            return context.getServerEcPublicKey();
        } else {
            return config.getDefaultServerEcPublicKey();
        }
    }

    @Override
    public EllipticCurveType getEcCurveType() {
        return EllipticCurveType.NAMED_CURVE; // We currentlyo nly support named
        // curves TODO
    }

    @Override
    public BigInteger getRsaModulus() {
        if (context.getRsaModulus() != null) {
            return context.getRsaModulus();
        } else {
            return config.getDefaultRSAModulus();
        }
    }

    @Override
    public BigInteger getServerRSAPublicKey() {
        if (context.getServerRSAPublicKey() != null) {
            return context.getServerRSAPublicKey();
        } else {
            return config.getDefaultServerRSAPublicKey();
        }
    }

    @Override
    public BigInteger getClientRSAPublicKey() {
        if (context.getClientRSAPublicKey() != null) {
            return context.getClientRSAPublicKey();
        } else {
            return config.getDefaultClientRSAPublicKey();
        }
    }

    @Override
    public byte[] getCertificateRequestContext() {
        if (context.getCertificateRequestContext() != null) {
            return context.getCertificateRequestContext();
        } else {
            return config.getDefaultCertificateRequestContext();
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (context.getServerHandshakeTrafficSecret() != null) {
            return context.getServerHandshakeTrafficSecret();
        } else {
            return config.getDefaultClientHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (context.getClientHandshakeTrafficSecret() != null) {
            return context.getClientHandshakeTrafficSecret();
        } else {
            return config.getDefaultClientHandshakeTrafficSecret();
        }
    }

    @Override
    public KSEntry getServerKSEntry() {
        if (context.getServerKSEntry() != null) {
            return context.getServerKSEntry();
        } else {
            return config.getDefaultServerKSEntry();
        }
    }
}
