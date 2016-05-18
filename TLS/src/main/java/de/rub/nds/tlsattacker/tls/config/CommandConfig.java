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
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.config.converters.CipherSuiteConverter;
import de.rub.nds.tlsattacker.tls.config.converters.ProtocolVersionConverter;
import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.HeartbeatModeConverter;
import de.rub.nds.tlsattacker.tls.config.converters.NamedCurveConverter;
import de.rub.nds.tlsattacker.tls.config.converters.PointFormatConverter;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.LinkedList;
import java.util.List;

/**
 * Configuration used for both the client and the server.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public abstract class CommandConfig {

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints help")
    protected boolean help;

    @Parameter(names = "-version", description = "Protocol version to use (it is also the only"
	    + " currently supported protocol version)", converter = ProtocolVersionConverter.class)
    protected ProtocolVersion protocolVersion = ProtocolVersion.TLS12;

    @Parameter(names = "-keystore", description = "Java Key Store (JKS) file to use as a certificate. In case TLS Client is used, the client sends ClientCertificate in the TLS handshake. Use keyword empty to enforce an empty ClientCertificate message.")
    protected String keystore;

    @Parameter(names = "-password", description = "Java Key Store (JKS) file password")
    protected String password;

    @Parameter(names = "-alias", description = "Alias of the key to be used from Java Key Store (JKS)")
    protected String alias;

    @Parameter(names = "-cipher", description = "TLS Ciphersuites to use, divided by a comma, e.g. "
	    + "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA", converter = CipherSuiteConverter.class)
    protected List<CipherSuite> cipherSuites;

    @Parameter(names = "-compression", description = "TLS compression methods to use, divided by a comma. "
	    + "(currently, only NULL compression is supported)", converter = CipherSuiteConverter.class)
    protected List<CompressionMethod> compressionMethods;

    @Parameter(names = "-named_curve", description = "Named curves to be used, divided by a comma. ", converter = NamedCurveConverter.class)
    protected List<NamedCurve> namedCurves;

    @Parameter(names = "-server_name", description = "Servername for HostName TLS extension.")
    protected String serverName;

    @Parameter(names = "-timeout", description = "Timeout for socket connection")
    protected int timeout;

    // @Parameter(names = "-nextprotoneg", description =
    // "Enables NPN extension, considering named protocols supported "
    // + "(comma-separated list), not supported yet TODO.")
    // protected List<String> nextProtoNeg;

    @Parameter(names = "-legacy_renegotiation", description = "Enables use of legacy renegotiation")
    protected boolean legacyRenegotiation;

    @Parameter(names = "-transport_handler_type", description = "Transport Handler type")
    protected TransportHandlerType transportHandlerType = TransportHandlerType.TCP;

    @Parameter(names = "-workflow_input", description = "This parameter allows you to load the whole workflow trace from the specified XML configuration file")
    protected String workflowInput;

    @Parameter(names = "-workflow_output", description = "This parameter allows you to serialize the whole workflow trace into a specific XML file")
    protected String workflowOutput;

    @Parameter(names = "-heartbeat_mode", description = "Sets the heartbeat mode (PEER_ALLOWED_TO_SEND or PEER_NOT_ALLOWED_TO_SEND)", converter = HeartbeatModeConverter.class)
    protected HeartbeatMode heartbeatMode;

    @Parameter(names = "-point_formats", description = "Sets the elliptic curve point formats", converter = PointFormatConverter.class)
    protected List<ECPointFormat> pointFormats;

    @Parameter(names = "-dynamic_workflow", description = "If this parameter is set, the workflow is only initialized with a ClientHello message (not yet implemented)")
    protected boolean dynamicWorkflow;

    @Parameter(names = "-verify_workflow_correctness", description = "If this parameter is set, the workflow correctness is evaluated after the worklow stops. This involves"
	    + "checks on the protocol message sequences.")
    protected boolean verifyWorkflowCorrectness;

    @Parameter(names = "-max_fragment_length", description = "Maximum fragment length definition for the max fragment length TLS extension (possible byte values 1,2,3, or 4)")
    protected Integer maxFragmentLength;

    @Parameter(names = "-tls_timeout", description = "Maximum time in milliseconds to wait for peer's response. Use different values for attack optimizations (e.g. 30 for OpenSSL localhost or 50 for JSSE localhost)")
    protected Integer tlsTimeout;

    @Parameter(names = "-client_authentication", description = "YES or NO")
    protected boolean clientAuthentication = false;

    @Parameter(names = "-session_resumption", description = "YES or NO")
    protected boolean sessionResumption = false;

    // todo define parameter
    protected List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

    public CommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	// cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
	compressionMethods = new LinkedList<>();
	compressionMethods.add(CompressionMethod.NULL);
	pointFormats = new LinkedList<>();
	pointFormats.add(ECPointFormat.UNCOMPRESSED);
	namedCurves = new LinkedList<>();
	namedCurves.add(NamedCurve.SECP192R1);
	namedCurves.add(NamedCurve.SECP256R1);
	namedCurves.add(NamedCurve.SECP384R1);
	namedCurves.add(NamedCurve.SECP521R1);
	// nextProtoNeg = new LinkedList<>();
	tlsTimeout = 400;
	alias = "";
	signatureAndHashAlgorithms = new LinkedList<>();
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA512));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA384));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA384));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA384));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA256));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA256));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA224));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA224));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA224));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA1));
	signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1));
    }

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }

    public ProtocolVersion getProtocolVersion() {
	return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public String getKeystore() {
	return keystore;
    }

    public void setKeystore(String keystore) {
	this.keystore = keystore;
    }

    public String getPassword() {
	return password;
    }

    public void setPassword(String password) {
	this.password = password;
    }

    public List<CipherSuite> getCipherSuites() {
	return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipher) {
	this.cipherSuites = cipher;
    }

    public String getServerName() {
	return serverName;
    }

    public void setServerName(String serverName) {
	this.serverName = serverName;
    }

    public int getTimeout() {
	return timeout;
    }

    public void setTimeout(int timeout) {
	this.timeout = timeout;
    }

    // public List<String> getNextProtoNeg() {
    // return nextProtoNeg;
    // }
    //
    // public void setNextProtoNeg(List<String> nextProtoNeg) {
    // this.nextProtoNeg = nextProtoNeg;
    // }

    public boolean isLegacyRenegotiation() {
	return legacyRenegotiation;
    }

    public void setLegacyRenegotiation(boolean legacyRenegotiation) {
	this.legacyRenegotiation = legacyRenegotiation;
    }

    public TransportHandlerType getTransportHandlerType() {
	return transportHandlerType;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
	this.transportHandlerType = transportHandlerType;
    }

    public String getWorkflowTraceConfigFile() {
	return workflowInput;
    }

    public void setWorkflowTraceConfigFile(String workflowTraceConfigFile) {
	this.workflowInput = workflowTraceConfigFile;
    }

    public String getWorkflowTraceOutputFile() {
	return workflowOutput;
    }

    public void setWorkflowTraceOutputFile(String workflowTraceOutputFile) {
	this.workflowOutput = workflowTraceOutputFile;
    }

    public List<CompressionMethod> getCompressionMethods() {
	return compressionMethods;
    }

    public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
	this.compressionMethods = compressionMethods;
    }

    public List<NamedCurve> getNamedCurves() {
	return namedCurves;
    }

    public void setNamedCurves(List<NamedCurve> namedCurves) {
	this.namedCurves = namedCurves;
    }

    public HeartbeatMode getHeartbeatMode() {
	return heartbeatMode;
    }

    public void setHeartbeatMode(HeartbeatMode heartbeatMode) {
	this.heartbeatMode = heartbeatMode;
    }

    public List<ECPointFormat> getPointFormats() {
	return pointFormats;
    }

    public boolean isDynamicWorkflow() {
	return dynamicWorkflow;
    }

    public void setDynamicWorkflow(boolean dynamicWorkflow) {
	this.dynamicWorkflow = dynamicWorkflow;
    }

    public boolean isVerifyWorkflowCorrectness() {
	return verifyWorkflowCorrectness;
    }

    public void setVerifyWorkflowCorrectness(boolean verifyWorkflowCorrectness) {
	this.verifyWorkflowCorrectness = verifyWorkflowCorrectness;
    }

    public void setPointFormats(List<ECPointFormat> pointFormats) {
	this.pointFormats = pointFormats;
    }

    public Integer getMaxFragmentLength() {
	return maxFragmentLength;
    }

    public void setMaxFragmentLength(Integer maxFragmentLength) {
	this.maxFragmentLength = maxFragmentLength;
    }

    public Integer getTlsTimeout() {
	return tlsTimeout;
    }

    public void setTlsTimeout(Integer tlsTimeout) {
	this.tlsTimeout = tlsTimeout;
    }

    public String getAlias() {
	return alias;
    }

    public void setAlias(String alias) {
	this.alias = alias;
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
	return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
	this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    public boolean isClientAuthentication() {
	return clientAuthentication;
    }

    public void setClientAuthentication(boolean clientAuthentication) {
	this.clientAuthentication = clientAuthentication;
    }

    public boolean isSessionResumption() {
	return sessionResumption;
    }

    public void setSessionResumption(boolean sessionResumption) {
	this.sessionResumption = sessionResumption;
    }
}
