/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.crypto.TlsMessageDigest;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TlsContext {

    // Default values
    private TlsConfig config;
    /**
     * master secret established during the handshake
     */
    private byte[] masterSecret = new byte[HandshakeByteLength.MASTER_SECRET];
    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
    /**
     * client random, including unix time
     */
    private byte[] clientRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server random, including unix time
     */
    private byte[] serverRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * selected cipher suite
     */
    private CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
    /**
     * compression algorithm
     */
    private CompressionMethod compressionMethod;
    /**
     * session ID
     */
    private byte[] sessionID = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server certificate parsed from the server certificate message
     */
    private Certificate serverCertificate;
    /**
     * client certificate parsed from the client certificate message
     */
    private Certificate clientCertificate;
    /**
     * server certificate from the server certificate message, in a nice x509
     * form
     */
    private X509CertificateObject x509ServerCertificateObject;
    /**
     * client certificate from the client certificate message, in a nice x509
     * form
     */
    private X509CertificateObject x509ClientCertificateObject;
    /**
     * EC context containing information about public/private key agreements,
     * curves, and point formats
     */
    private TlsECContext ecContext;
    /**
     * Server DH parameters
     */
    private ServerDHParams serverDHParameters;
    /**
     * Server DH Private Key
     */
    private DHPrivateKeyParameters serverDHPrivateKeyParameters;
    /**
     * workflow trace containing all the messages exchanged during the
     * communication
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace;

    private TlsMessageDigest digest;

    private RecordHandler recordHandler;

    private TransportHandler transportHandler;

    private ConnectionEnd talkingConnectionEnd = ConnectionEnd.CLIENT;

    /**
     * DTLS Cookie
     */
    private byte[] dtlsHandshakeCookie = new byte[0];

    public TlsContext() {
        digest = new TlsMessageDigest();
        ecContext = new TlsECContext();
        config = new TlsConfig();
    }

    public TlsContext(TlsConfig config) {
        digest = new TlsMessageDigest();
        ecContext = new TlsECContext();
        this.config = config;
    }

    public ConnectionEnd getTalkingConnectionEnd() {
        return talkingConnectionEnd;
    }

    public void setTalkingConnectionEnd(ConnectionEnd talkingConnectionEnd) {
        this.talkingConnectionEnd = talkingConnectionEnd;
    }

    public TlsConfig getConfig() {
        return config;
    }

    public void initiliazeTlsMessageDigest() {
        try {
            DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(config.getProtocolVersion(),
                    selectedCipherSuite);
            digest.initializeDigestAlgorithm(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public byte[] getServerClientRandom() {
        return ArrayConverter.concatenate(serverRandom, clientRandom);
    }

    public CipherSuite getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setSelectedCipherSuite(CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public byte[] getClientServerRandom() {
        return ArrayConverter.concatenate(clientRandom, serverRandom);
    }

    public byte[] getPreMasterSecret() {
        return preMasterSecret;
    }

    public void setPreMasterSecret(byte[] preMasterSecret) {
        this.preMasterSecret = preMasterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(CompressionMethod compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
        this.workflowTrace = workflowTrace;
    }

    public TlsECContext getEcContext() {
        return ecContext;
    }

    public void setEcContext(TlsECContext ecContext) {
        this.ecContext = ecContext;
    }

    public Certificate getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public Certificate getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(Certificate clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public X509CertificateObject getX509ServerCertificateObject() {
        return x509ServerCertificateObject;
    }

    public void setX509ServerCertificateObject(X509CertificateObject x509ServerCertificateObject) {
        this.x509ServerCertificateObject = x509ServerCertificateObject;
    }

    public X509CertificateObject getX509ClientCertificateObject() {
        return x509ClientCertificateObject;
    }

    public void setX509ClientCertificateObject(X509CertificateObject x509ClientCertificateObject) {
        this.x509ClientCertificateObject = x509ClientCertificateObject;
    }

    public ServerDHParams getServerDHParameters() {
        return serverDHParameters;
    }

    public void setServerDHParameters(ServerDHParams serverDHParameters) {
        this.serverDHParameters = serverDHParameters;
    }

    public DHPrivateKeyParameters getServerDHPrivateKeyParameters() {
        return serverDHPrivateKeyParameters;
    }

    public void setServerDHPrivateKeyParameters(DHPrivateKeyParameters serverDHPrivateKeyParameters) {
        this.serverDHPrivateKeyParameters = serverDHPrivateKeyParameters;
    }

    public TlsMessageDigest getDigest() {
        return digest;
    }

    public void setDtlsHandshakeCookie(byte[] cookie) {
        this.dtlsHandshakeCookie = cookie;
    }

    public byte[] getDtlsHandshakeCookie() {
        return dtlsHandshakeCookie;
    }

    public TransportHandler getTransportHandler() {
        return transportHandler;
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        this.transportHandler = transportHandler;
    }

    public RecordHandler getRecordHandler() {
        return recordHandler;
    }

    public void setRecordHandler(RecordHandler recordHandler) {
        this.recordHandler = recordHandler;
    }
}
