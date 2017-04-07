/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.tls.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionProbe extends TLSProbe {

    public ProtocolVersionProbe(ScannerConfig config) {
        super("ProtocolVersion", config);
    }

    @Override
    public ProbeResult call() {
        List<ResultValue> resultList = new LinkedList<>();
        List<TLSCheck> checkList = new LinkedList<>();
        LOGGER.info("Testing SSL2:");
        boolean result = isSSL2Supported();
        resultList.add(new ResultValue("SSL 2", "" + result));
        checkList.add(new TLSCheck(result, CheckType.PROTOCOLVERSION_SSL2, getConfig().getLanguage()));
        LOGGER.info("Testing SSL3:");
        result = isProtocolVersionSupported(ProtocolVersion.SSL3);
        resultList.add(new ResultValue("SSL 3", "" + result));
        checkList.add(new TLSCheck(result, CheckType.PROTOCOLVERSION_SSL3, getConfig().getLanguage()));
        LOGGER.info("Testing TLS 1.0:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS10);
        resultList.add(new ResultValue("TLS 1.0", "" + result));
        LOGGER.info("Testing TLS 1.1:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS11);
        resultList.add(new ResultValue("TLS 1.1", "" + result));
        LOGGER.info("Testing TLS 1.2:");
        result = isProtocolVersionSupported(ProtocolVersion.TLS12);
        resultList.add(new ResultValue("TLS 1.2", "" + result));
        return new ProbeResult(getProbeName(), resultList, checkList);

    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest) {
        TlsConfig tlsConfig = getConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setSupportedCiphersuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setEnforceSettings(true);
        if (toTest != ProtocolVersion.SSL2) {
            tlsConfig.setAddServerNameIndicationExtension(false);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        } else {
            // Dont send extensions if we are in sslv2
            tlsConfig.setAddECPointFormatExtension(false);
            tlsConfig.setAddEllipticCurveExtension(false);
            tlsConfig.setAddHeartbeatExtension(false);
            tlsConfig.setAddMaxFragmentLengthExtenstion(false);
            tlsConfig.setAddServerNameIndicationExtension(false);
            tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(false);
        }
        List<NamedCurve> namedCurves = Arrays.asList(NamedCurve.values());

        tlsConfig.setNamedCurves(namedCurves);
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(tlsConfig);
        trace.add(new SendAction(message));
        trace.add(new ReceiveAction(new ArbitraryMessage()));
        tlsConfig.setWorkflowTrace(trace);
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
        }
        List<HandshakeMessage> messages = trace
                .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO);
        if (messages.isEmpty()) {
            LOGGER.warn(trace.toString());
            return false;
        } else {
            LOGGER.warn(trace.toString());
            LOGGER.warn("Selected Version:" + tlsContext.getSelectedProtocolVersion().name());
            return tlsContext.getSelectedProtocolVersion() == toTest;
        }
    }

    private boolean isSSL2Supported() {
        TlsConfig tlsConfig = getConfig().createConfig();
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.SSL2);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setExecutorType(ExecutorType.SSL2);
        tlsConfig.setRecordLayerType(RecordLayerType.BLOB);
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new SSL2ClientHelloMessage(tlsConfig)));
        trace.add(new ReceiveAction(new ArbitraryMessage()));
        tlsConfig.setWorkflowTrace(trace);
        TlsContext context = new TlsContext(tlsConfig);
        context.setSessionID(new byte[0]);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(ExecutorType.TLS, context);
        executor.executeWorkflow();
        List<ProtocolMessage> messages = trace.getAllActuallyReceivedMessages();
        for (ProtocolMessage message : messages) {
            if (message instanceof SSL2ServerHelloMessage) {
                return true;
            }
        }
        return false;
    }

}
