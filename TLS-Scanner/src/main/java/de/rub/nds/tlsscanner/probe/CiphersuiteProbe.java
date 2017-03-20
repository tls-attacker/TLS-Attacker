/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.flaw.FlawLevel;
import de.rub.nds.tlsscanner.report.ResultValue;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteProbe extends TLSProbe {

    private static final Logger LOGGER = LogManager.getLogger(CiphersuiteProbe.class);

    private static CipherSuite blacklistedCiphersuites[] = {};

    private List<ProtocolVersion> protocolVersions;

    public CiphersuiteProbe(String serverHost) {
        super("Ciphersuite", serverHost);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
    }

    @Override
    public ProbeResult call() {
        LOGGER.info("Starting CiphersuiteProbe");
        Set<CipherSuite> supportedCiphersuites = new HashSet<>();

        for (ProtocolVersion version : protocolVersions) {
            LOGGER.info("Testing:" + version.name());
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            supportedCiphersuites.addAll(getSupportedCipherSuitesFromList(toTestList, version));
        }
        List<ResultValue> resultList = new LinkedList<>();
        List<ConfigurationFlaw> flawList = new LinkedList<>();
        for (CipherSuite suite : supportedCiphersuites) {
            resultList.add(new ResultValue("Ciphersuite", suite.name()));
            if (suite.name().contains("EXPORT")) {
                flawList.add(new ConfigurationFlaw("Export Cipher", FlawLevel.SEVERE, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden. Da export Ciphersuites zu schwach sind.",
                        "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("RC4")) {
                flawList.add(new ConfigurationFlaw("RC4 Cipher", FlawLevel.MEDIUM, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden. Da der RC4 Algorithmus als unsicher gilt.",
                        "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("anon")) {
                flawList.add(new ConfigurationFlaw("Anon Cipher", FlawLevel.SEVERE, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden. Da anonymous Ciphersuites unsicher sind.",
                        "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("CBC")) {
                flawList.add(new ConfigurationFlaw("CBC Cipher", FlawLevel.MINOR, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden. Da CBC Ciphersuites unsicher sind.",
                        "Deaktivieren sie die Ciphersuite"));
            }
        }

        return new ProbeResult(getProbeName(), resultList, flawList);

    }

    public List<CipherSuite> getSupportedCipherSuitesFromList(List<CipherSuite> toTestList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            TlsConfig config = new TlsConfig();
            config.setHost(getServerHost());
            config.setSupportedCiphersuites(listWeSupport);
            config.setHighestProtocolVersion(version);
            WorkflowTrace trace = new WorkflowTrace();
            trace.add(new SendAction(new ClientHelloMessage(config)));
            trace.add(new ReceiveAction(new ArbitraryMessage()));
            config.setWorkflowTrace(trace);
            TlsContext tlsContext = new TlsContext(config);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    config.getExecutorType(), tlsContext);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                ex.printStackTrace();
                supportsMore = false;
            }
            if (!trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO).isEmpty()) {
                LOGGER.info("Server chose " + tlsContext.getSelectedCipherSuite().name());
                supportsMore = true;
                supported.add(tlsContext.getSelectedCipherSuite());
                listWeSupport.remove(tlsContext.getSelectedCipherSuite());
            } else {
                supportsMore = false;
                LOGGER.info("Server did not send ServerHello");
            }
        } while (supportsMore);
        return supported;
    }

}
