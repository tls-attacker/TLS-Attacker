/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.crypto.TlsMessageDigest;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TlsContext {

    /**
     * SSL/TLS protocol version
     */
    private ProtocolVersion protocolVersion = ProtocolVersion.TLS12;
    /**
     * Indicates if we are executing a server or client
     */
    private ConnectionEnd myConnectionEnd = ConnectionEnd.CLIENT;
    /**
     * master secret established during the handshake
     */
    private byte[] masterSecret = new byte[HandshakeByteLength.MASTER_SECRET];
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
    private CipherSuite selectedCipherSuite = CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA;
    /**
     * compression algorithm
     */
    private CompressionMethod compressionMethod;
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
     * workflow trace containing all the messages exchanged during the
     * communication
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace;
    /**
     * List of preconfigured protocol messages by the workflow configuration
     * factory. In case the real message order of sent messages was modified,
     * one can compare it to the preconfigured order and find differences.
     */
    private List<ProtocolMessageTypeHolder> preconfiguredProtocolMessages;
    /**
     * keystore for storing client / server certificates
     */
    private KeyStore keyStore;
    /**
     * alias for the used key in the keystore
     */
    private String alias;
    /**
     * key store password
     */
    private String password;

    private final TlsMessageDigest digest;

    private LinkedList<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;

    public TlsContext() {
	ecContext = new TlsECContext();
	protocolVersion = ProtocolVersion.TLS12;
	try {
	    digest = new TlsMessageDigest(this.protocolVersion);
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

    public ProtocolVersion getProtocolVersion() {
	return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public ConnectionEnd getMyConnectionEnd() {
	return myConnectionEnd;
    }

    public void setMyConnectionEnd(ConnectionEnd myConnectionEnd) {
	this.myConnectionEnd = myConnectionEnd;
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

    public List<ProtocolMessageTypeHolder> getPreconfiguredProtocolMessages() {
	return preconfiguredProtocolMessages;
    }

    public void setPreconfiguredProtocolMessages(List<ProtocolMessageTypeHolder> preconfiguredProtocolMessages) {
	this.preconfiguredProtocolMessages = preconfiguredProtocolMessages;
    }

    public KeyStore getKeyStore() {
	return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
	this.keyStore = keyStore;
    }

    public String getAlias() {
	return alias;
    }

    public void setAlias(String alias) {
	this.alias = alias;
    }

    public String getPassword() {
	return password;
    }

    public void setPassword(String password) {
	this.password = password;
    }

    public TlsMessageDigest getDigest() {
	return digest;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
	return supportedSignatureAndHashAlgorithms;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsForRSA() {
	LinkedList<SignatureAndHashAlgorithm> rsaAlgorithms = new LinkedList<>();
	for (SignatureAndHashAlgorithm alg : supportedSignatureAndHashAlgorithms) {
	    if (alg.getSignatureAlgorithm() == SignatureAlgorithm.RSA) {
		rsaAlgorithms.add(alg);
	    }
	}
	return rsaAlgorithms;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsForEC() {
	LinkedList<SignatureAndHashAlgorithm> ecAlgorithms = new LinkedList<>();
	for (SignatureAndHashAlgorithm alg : supportedSignatureAndHashAlgorithms) {
	    if (alg.getSignatureAlgorithm() == SignatureAlgorithm.ECDSA) {
		ecAlgorithms.add(alg);
	    }
	}
	return ecAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(
	    LinkedList<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
	this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

}
