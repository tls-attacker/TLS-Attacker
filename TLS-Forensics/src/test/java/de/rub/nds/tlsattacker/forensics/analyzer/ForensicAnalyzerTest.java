/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.forensics.analyzer;

import static org.assertj.core.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.function.Predicate;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import org.assertj.core.api.Condition;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import org.junit.Ignore;

public class ForensicAnalyzerTest {

    static Condition<TlsAction> hasNonEmptyMessages = new Condition<TlsAction>() {
        @Override
        public boolean matches(TlsAction value) {
            return value.isMessageAction() && !((MessageAction) value).getMessages().isEmpty();
        }
    };

    static Condition<TlsAction> hasAnyUnknownMessages = new Condition<TlsAction>() {
        @Override
        public boolean matches(TlsAction value) {
            return value.isMessageAction() && ((MessageAction) value).getMessages().stream().anyMatch(it -> {
                return it instanceof TlsMessage
                    && ((TlsMessage) it).getProtocolMessageType() == ProtocolMessageType.UNKNOWN;
            });
        }
    };

    @Test
    @Ignore
    public void getRealWorkflowTraceWithRsaPrivateKey() throws JAXBException, IOException, XMLStreamException {
        BigInteger rsaPrivateKey = new BigInteger(
            "144490376376406540965205589156240569211382533466359849946728402570136249818055405537488044194647351959609489426069723713548216483327106438912858757254792530891714061133579603846889282342802418516591741975737381214992723907604280314805065261718449369587056911550617209133141490404695448146483761702254794149121");
        WorkflowTrace executedWorkflow =
            WorkflowTraceSerializer.secureRead(this.getClass().getResourceAsStream("/raw-trace-55859-4433.xml"));
        ForensicAnalyzer forensicAnalyzer = new ForensicAnalyzer();
        WorkflowTrace realWorkflowTrace = forensicAnalyzer.getRealWorkflowTrace(executedWorkflow, rsaPrivateKey);
        WorkflowTraceSerializer.write(System.out, realWorkflowTrace);
        assertThat(realWorkflowTrace.getTlsActions()).hasSize(4);
        assertThat(realWorkflowTrace.getTlsActions()).are(hasNonEmptyMessages);
        assertThat(realWorkflowTrace.getTlsActions()).areNot(hasAnyUnknownMessages);
    }
}
