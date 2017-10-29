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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public abstract class Chooser {

    protected static final Logger LOGGER = LogManager.getLogger(Chooser.class.getName());

    protected final TlsContext context;

    protected final Config config;

    public Chooser(TlsContext context, Config config) {
        this.config = config;
        this.context = context;
    }

    public Config getConfig() {
        return config;
    }

    public TlsContext getContext() {
        return context;
    }

    public abstract List<ECPointFormat> getClientSupportedPointFormats();

    public abstract SignatureAndHashAlgorithm getSelectedSigHashAlgorithm();

    public abstract List<NamedCurve> getClientSupportedNamedCurves();

    public abstract List<ECPointFormat> getServerSupportedPointFormats();

    public abstract List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms();

    public abstract List<SNIEntry> getClientSNIEntryList();

    public abstract ProtocolVersion getLastRecordVersion();

    public abstract byte[] getDistinguishedNames();

    public abstract List<ClientCertificateType> getClientCertificateTypes();

    public abstract MaxFragmentLength getMaxFragmentLength();

    public abstract HeartbeatMode getHeartbeatMode();

    public abstract boolean isExtendedMasterSecretExtension();

    public abstract List<CompressionMethod> getClientSupportedCompressions();

    public abstract List<CipherSuite> getClientSupportedCiphersuites();

    public abstract List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms();

    public abstract ProtocolVersion getSelectedProtocolVersion();

    public abstract ProtocolVersion getHighestClientProtocolVersion();

    public abstract ConnectionEndType getTalkingConnectionEnd();

    public abstract byte[] getMasterSecret();

    public abstract CipherSuite getSelectedCipherSuite();

    public abstract byte[] getPreMasterSecret();

    public abstract byte[] getClientRandom();

    public abstract byte[] getServerRandom();

    public abstract CompressionMethod getSelectedCompressionMethod();

    public abstract byte[] getClientSessionId();

    public abstract byte[] getServerSessionId();

    public abstract byte[] getDtlsCookie();

    public abstract TransportHandler getTransportHandler();

    public abstract PRFAlgorithm getPRFAlgorithm();

    public abstract byte[] getSessionTicketTLS();

    public abstract byte[] getSignedCertificateTimestamp();

    public abstract TokenBindingVersion getTokenBindingVersion();

    public abstract List<TokenBindingKeyParameters> getTokenBindingKeyParameters();

    public abstract BigInteger getDhModulus();

    public abstract BigInteger getDhGenerator();

    public abstract BigInteger getDhServerPrivateKey();

    public abstract BigInteger getDhClientPrivateKey();

    public abstract BigInteger getDhServerPublicKey();

    public abstract BigInteger getDhClientPublicKey();

    public abstract BigInteger getSRPModulus();

    public abstract BigInteger getSRPGenerator();

    public abstract BigInteger getSRPServerPrivateKey();

    public abstract BigInteger getSRPServerPublicKey();

    public abstract BigInteger getSRPClientPrivateKey();

    public abstract BigInteger getSRPClientPublicKey();

    public abstract byte[] getSRPSalt();

    public abstract byte[] getSRPPassword();

    public abstract byte[] getSRPIdentity();

    public abstract BigInteger getServerEcPrivateKey();

    public abstract BigInteger getClientEcPrivateKey();

    public abstract NamedCurve getSelectedCurve();

    public abstract CustomECPoint getClientEcPublicKey();

    public abstract CustomECPoint getServerEcPublicKey();

    public abstract EllipticCurveType getEcCurveType();

    public abstract BigInteger getRsaModulus();

    public abstract BigInteger getServerRSAPublicKey();

    public abstract BigInteger getClientRSAPublicKey();

    public abstract byte[] getCertificateRequestContext();

    public abstract byte[] getServerHandshakeTrafficSecret();

    public abstract byte[] getClientHandshakeTrafficSecret();

    public abstract KSEntry getServerKSEntry();
}
