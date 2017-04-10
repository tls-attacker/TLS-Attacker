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
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteOrderProbe extends TLSProbe {

    public CiphersuiteOrderProbe(ScannerConfig config) {
        super("CiphersuiteOrder", config);
    }

    @Override
    public ProbeResult call() {
        LOGGER.info("Starting CipherSuiteOrder Test");

        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        Collections.reverseOrder();
        CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);

        List<ResultValue> resultList = new LinkedList<>();
        resultList.add(new ResultValue("Server Enforces Ciphersuite Order", ""
                + (firstSelectedCipherSuite == secondSelectedCipherSuite)));
        List<TLSCheck> checkList = new LinkedList<>();
        checkList.add(new TLSCheck(firstSelectedCipherSuite != secondSelectedCipherSuite,
                CheckType.CIPHERSUITEORDER_ENFORCED, getConfig().getLanguage()));
        return new ProbeResult(getProbeName(), resultList, checkList);

    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {

        TlsConfig tlsConfig = getConfig().createConfig();
        tlsConfig.setSupportedCiphersuites(toTestList);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddServerNameIndicationExtension(false);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
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
            ex.printStackTrace();
        }
        return tlsContext.getSelectedCipherSuite();
    }
}
