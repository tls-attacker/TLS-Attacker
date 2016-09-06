/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.automata;

//import WorkFlowType.MessageFlow;
//import WorkFlowType.WorkflowTraceType;
//
//import java.util.Set;
//import net.automatalib.automata.fsa.impl.compact.CompactDFA;
//import net.automatalib.words.impl.SimpleAlphabet;
//import org.jgrapht.graph.DirectedMultigraph;
//import java.util.Collection;
//import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowAutomataBuilder {
    // public static CompactDFA<MessageFlow>
    // generateWorkflowAutomata(Set<WorkflowTraceType> typeList)
    // {
    // SimpleAlphabet<MessageFlow> alpha = new SimpleAlphabet<>();
    // CompactDFA<MessageFlow> dfa = new CompactDFA<>(alpha);
    // int uniquer = 0;
    // int start = dfa.addInitialState(false);
    //
    // for(WorkflowTraceType type:typeList)
    // {
    // int current = start;
    // List<MessageFlow> flows = type.getFlows();
    // for(MessageFlow flow : flows)
    // {
    //
    // Collection<? extends Integer> temp = dfa.getTransitions(current, flow);
    // if(temp.isEmpty())
    // {
    // uniquer++;
    // flow.setUniquer(uniquer);
    // int newState = dfa.addState();
    // dfa.setAccepting(newState, true);
    // dfa.addTransition(start, flow, newState);
    // current = newState;
    // }
    // else
    // {
    // if(temp.size()>1)
    // {
    // System.out.println("ERROR");
    // }
    // current = (int) temp.toArray()[0];
    // }
    // }
    // }
    //
    // return dfa;
    // }
    // public static MessageFlow returnOutGoingFlow(DirectedMultigraph<Integer,
    // MessageFlow> graph, MessageFlow flow, Integer current)
    // {
    // for(MessageFlow f : graph.outgoingEdgesOf(current))
    // {
    // if(f.getIssuer() == flow.getIssuer() &&
    // f.getMessage()==flow.getMessage())
    // {
    // return f;
    // }
    // }
    // return null;
    // }
}
