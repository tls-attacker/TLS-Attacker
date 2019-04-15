/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.forensics.analyzer;

import static org.assertj.core.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.function.Predicate;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.assertj.core.api.Condition;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class ForensicAnalyzerTest {

    static Condition<TlsAction> HasNonEmptyMessages = new Condition<TlsAction>() {
        @Override
        public boolean matches(TlsAction value) {
            return value.isMessageAction() && !((MessageAction) value).getMessages().isEmpty();
        }
    };

    static Condition<TlsAction> HasAnyUnknownMessages = new Condition<TlsAction>() {
        @Override
        public boolean matches(TlsAction value) {
            return value.isMessageAction()
                    && ((MessageAction) value).getMessages().stream().anyMatch(new Predicate<ProtocolMessage>() {
                        @Override
                        public boolean test(ProtocolMessage it) {
                            return it.getProtocolMessageType() == ProtocolMessageType.UNKNOWN;
                        }
                    });
        }
    };

    @Test
    public void getRealWorkflowTraceWithRsaPrivateKey() throws JAXBException, IOException, XMLStreamException {
        BigInteger rsaPrivateKey = new BigInteger(
                "85548662860141184374324530555238509614883952982620072870709568174736062736668245972563539402639205869920221700560171344685970714363510720220745130046971566732302115238815832932643167813406896458276197575984093928858171631387512634598137747935976012917411161520559159507455213892144929209093453512803543231233");
        WorkflowTrace executedWorkflow = WorkflowTraceSerializer.read(this.getClass().getResourceAsStream(
                "/raw-trace-55859-4433.xml"));
        ForensicAnalyzer forensicAnalyzer = new ForensicAnalyzer();
        WorkflowTrace realWorkflowTrace = forensicAnalyzer.getRealWorkflowTrace(executedWorkflow, rsaPrivateKey);
        // System.out.println(WorkflowTraceSerializer.write(realWorkflowTrace));
        assertThat(realWorkflowTrace.getTlsActions()).hasSize(4);
        assertThat(realWorkflowTrace.getTlsActions()).are(HasNonEmptyMessages);
        assertThat(realWorkflowTrace.getTlsActions()).areNot(HasAnyUnknownMessages);
    }
}
