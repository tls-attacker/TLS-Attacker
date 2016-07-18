/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package FlowVisualisation;

import WorkFlowType.MessageFlow;
import javax.swing.JFrame;
import org.jgraph.JGraph;
import org.jgrapht.Graph;
import java.awt.Color;
import java.awt.geom.Rectangle2D;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import org.jgraph.JGraph;
import org.jgraph.graph.AttributeMap;
import org.jgraph.graph.DefaultEdge;
import org.jgraph.graph.DefaultGraphCell;
import org.jgraph.graph.DefaultGraphModel;
import org.jgraph.graph.GraphConstants;
import org.jgraph.graph.GraphModel;
import org.jgrapht.ext.JGraphModelAdapter;
import org.jgrapht.graph.DirectedMultigraph;
import org.jgrapht.graph.ListenableDirectedGraph;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class GraphWindow {

    public static void showWindow(DirectedMultigraph<Integer, MessageFlow> incomingGraph) {

	System.out.println(incomingGraph.edgeSet().size());
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
}
