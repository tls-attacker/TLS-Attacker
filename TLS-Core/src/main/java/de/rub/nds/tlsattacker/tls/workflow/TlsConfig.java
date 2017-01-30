/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.security.KeyStore;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsConfig {

    /**
     * Default value for PtocolverionFields
     */
    private ProtocolVersion protocolVersion = ProtocolVersion.TLS12;

    /**
     * Indicates which ConnectionEnd we are
     */
    private ConnectionEnd myConnectionEnd = ConnectionEnd.CLIENT;

    /**
     * The Workflow Trace that should be executed
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace = null;

    /**
     * Keystore for storing client / server certificates
     */
    private KeyStore keyStore = null;
    /**
     * Alias for the used key in the Keystore
     */
    private String alias = null;
    /**
     * keystore password
     */
    private String password = null;
    /**
     * host to connect
     */
    private String host = "127.0.0.1";
    /**
     * If default generated WorkflowTraces should contain client Authentication
     */
    private boolean clientAuthentication = false;
    /**
     * SessionResumptionWorkflow
     */
    private boolean sessionResumption = false;
    /**
     * RenegotiationWorkflow
     */
    private boolean renegotiation = false;
    /**
     * Man_in_the_Middle_Workflow
     */
    private boolean mitm = false;
    /**
     * Which Signature and Hash algorithms we support
     */
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;
    /**
     * If we are in Fuzzing mode, eg ignore error and try to proceed as good as
     * possible
     */
    private boolean fuzzingMode = false;
    /**
     * Which Ciphersuites we support by default
     */
    private List<CipherSuite> supportedCiphersuites;
    /**
     * Which compression methods we support by default
     */
    private List<CompressionMethod> supportedCompressionMethods;
    /**
     * If we are a dynamic workflow //TODO
     */
    private boolean dynamicWorkflow = false;
    /**
     * Supported ECPointFormats by default
     */
    private List<ECPointFormat> pointFormats;
    /**
     * Supported namedCurves by default
     */
    private List<NamedCurve> namedCurves;
    /**
     * Which heartBeat mode we are in
     */
    private HeartbeatMode heartbeatMode;
    /**
     * Hostname in SNI Extension
     */
    private String sniHostname;
    /**
     * Should we terminate the connection on a wrong SNI ?
     */
    private boolean sniHostnameFatal;
    /**
     * Server port used
     */
    private int serverPort;
    /**
     * MaxFragmentLength in MaxFragmentLengthExtension
     */
    private MaxFragmentLength maxFragmentLength;
    /**
     * Default Timeout we wait for TLSMessages
     */
    private int tlsTimeout = 400;
    /**
     * Default Timeout for the Connection
     */
    private int timeout = 1000;
    /**
     * Transporthandler Type that shall be used
     */
    private TransportHandlerType transportHandlerType;
    /**
     * If the workflow should be verified //TODO
     */
    private boolean verifyWorkflow = false;
    /**
     * If we should use a workflow trace specified in File
     */
    private String workflowInput;
    /**
     * If we should output an executed workflowtrace to a specified file
     */
    private String workflowOutput;
    /**
     * The Type of workflow trace that should be generated
     */
    private WorkflowTraceType workflowTraceType;
    /**
     * If the Default generated workflowtrace should contain Application data
     * send by servers
     */
    private boolean serverSendsApplicationData;
    /**
     * If we generate ClientHello with the ECPointFormat extension
     */
    private boolean addECPointFormatExtension = false;
    /**
     * If we generate ClientHello with the EllipticCurveExtension extension
     */
    private boolean addEllipticCurveExtension = false;
    /**
     * If we generate ClientHello with the Heartbeat extension
     */
    private boolean addHeartbeatExtension = false;
    /**
     * If we generate ClientHello with the MaxFragmentLength extension
     */
    private boolean addMaxFragmentLengthExtenstion = false;
    /**
     * If we generate ClientHello with the ServerNameIndication extension
     */
    private boolean addServerNameIndicationExtension = false;
    /**
     * If we generate ClientHello with the SignatureAndHashAlgorithm extension
     */
    private boolean addSignatureAndHashAlgrorithmsExtension = false;

    public TlsConfig() {
        supportedSignatureAndHashAlgorithms = new LinkedList<>();
        supportedCompressionMethods = new LinkedList<>();
        supportedCompressionMethods.add(CompressionMethod.NULL);
        supportedCiphersuites = new LinkedList<>();
        supportedCiphersuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP192R1);
        namedCurves.add(NamedCurve.SECP256R1);
        namedCurves.add(NamedCurve.SECP384R1);
        namedCurves.add(NamedCurve.SECP521R1);
        pointFormats = new LinkedList<>();
    }

    public boolean isServerSendsApplicationData() {
        return serverSendsApplicationData;
    }

    public void setServerSendsApplicationData(boolean serverSendsApplicationData) {
        this.serverSendsApplicationData = serverSendsApplicationData;
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    public String getWorkflowOutput() {
        return workflowOutput;
    }

    public void setWorkflowOutput(String workflowOutput) {
        this.workflowOutput = workflowOutput;
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    public boolean isVerifyWorkflow() {
        return verifyWorkflow;
    }

    public void setVerifyWorkflow(boolean verifyWorkflow) {
        this.verifyWorkflow = verifyWorkflow;
    }

    public TransportHandlerType getTransportHandlerType() {
        return transportHandlerType;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    public int getTlsTimeout() {
        return tlsTimeout;
    }

    public void setTlsTimeout(int tlsTimeout) {
        this.tlsTimeout = tlsTimeout;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public boolean isSniHostnameFatal() {
        return sniHostnameFatal;
    }

    public void setSniHostnameFatal(boolean sniHostnameFatal) {
        this.sniHostnameFatal = sniHostnameFatal;
    }

    public MaxFragmentLength getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(MaxFragmentLength maxFragmentLengthConfig) {
        this.maxFragmentLength = maxFragmentLengthConfig;
    }

    public String getSniHostname() {
        return sniHostname;
    }

    public void setSniHostname(String SniHostname) {
        this.sniHostname = SniHostname;
    }

    public boolean isDynamicWorkflow() {
        return dynamicWorkflow;
    }

    public void setDynamicWorkflow(boolean dynamicWorkflow) {
        this.dynamicWorkflow = dynamicWorkflow;
    }

    public List<CipherSuite> getSupportedCiphersuites() {
        return supportedCiphersuites;
    }

    public void setSupportedCiphersuites(List<CipherSuite> supportedCiphersuites) {
        this.supportedCiphersuites = supportedCiphersuites;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
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

    public ConnectionEnd getMyConnectionPeer() {
        return myConnectionEnd == ConnectionEnd.CLIENT ? ConnectionEnd.SERVER : ConnectionEnd.CLIENT;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
        this.workflowTrace = workflowTrace;
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

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
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

    public boolean isRenegotiation() {
        return renegotiation;
    }

    public void setRenegotiation(boolean renegotiation) {
        this.renegotiation = renegotiation;
    }

    public boolean isMitm() {
        return mitm;
    }

    public void setMitm(boolean mitm) {
        this.mitm = mitm;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public boolean isFuzzingMode() {
        return fuzzingMode;
    }

    public void setFuzzingMode(boolean fuzzingMode) {
        this.fuzzingMode = fuzzingMode;
    }

    public List<ECPointFormat> getPointFormats() {
        return pointFormats;
    }

    public void setPointFormats(List<ECPointFormat> pointFormats) {
        this.pointFormats = pointFormats;
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

    public boolean isAddECPointFormatExtension() {
        return addECPointFormatExtension;
    }

    public void setAddECPointFormatExtension(boolean addECPointFormatExtension) {
        this.addECPointFormatExtension = addECPointFormatExtension;
    }

    public boolean isAddEllipticCurveExtension() {
        return addEllipticCurveExtension;
    }

    public void setAddEllipticCurveExtension(boolean addEllipticCurveExtension) {
        this.addEllipticCurveExtension = addEllipticCurveExtension;
    }

    public boolean isAddHeartbeatExtension() {
        return addHeartbeatExtension;
    }

    public void setAddHeartbeatExtension(boolean addHeartbeatExtension) {
        this.addHeartbeatExtension = addHeartbeatExtension;
    }

    public boolean isAddMaxFragmentLengthExtenstion() {
        return addMaxFragmentLengthExtenstion;
    }

    public void setAddMaxFragmentLengthExtenstion(boolean addMaxFragmentLengthExtenstion) {
        this.addMaxFragmentLengthExtenstion = addMaxFragmentLengthExtenstion;
    }

    public boolean isAddServerNameIndicationExtension() {
        return addServerNameIndicationExtension;
    }

    public void setAddServerNameIndicationExtension(boolean addServerNameIndicationExtension) {
        this.addServerNameIndicationExtension = addServerNameIndicationExtension;
    }

    public boolean isAddSignatureAndHashAlgrorithmsExtension() {
        return addSignatureAndHashAlgrorithmsExtension;
    }

    public void setAddSignatureAndHashAlgrorithmsExtension(boolean addSignatureAndHashAlgrorithmsExtension) {
        this.addSignatureAndHashAlgrorithmsExtension = addSignatureAndHashAlgrorithmsExtension;
    }
}
