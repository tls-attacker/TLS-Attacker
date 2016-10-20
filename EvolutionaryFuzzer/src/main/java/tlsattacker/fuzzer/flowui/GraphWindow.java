/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.flowui;

import tlsattacker.fuzzer.workflow.MessageFlow;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import org.jgraph.JGraph;
import org.jgrapht.ext.JGraphModelAdapter;
import org.jgrapht.graph.DirectedMultigraph;

/**
 * A window which tries to visualizes a directed graph
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class GraphWindow {

    public static void showWindow(DirectedMultigraph<Integer, MessageFlow> incomingGraph) {

	JFrame frame = new JFrame();
	frame.setSize(400, 400);
	JGraphModelAdapter adapter = new JGraphModelAdapter(incomingGraph);

	JGraph jgraph = new JGraph(adapter);

	frame.getContentPane().add(jgraph);
	frame.setVisible(true);
	while (true) {
	    try {
		Thread.sleep(2000);
	    } catch (InterruptedException ex) {
		Logger.getLogger(GraphWindow.class.getName()).log(Level.SEVERE, null, ex);
	    }
	}
    }

    private static final Logger LOG = Logger.getLogger(GraphWindow.class.getName());

}
