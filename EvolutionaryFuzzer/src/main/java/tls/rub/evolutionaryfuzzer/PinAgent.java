/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DefaultDirectedGraph;
import tls.branchtree.BranchTrace;
import tls.branchtree.CountEdge;
import tls.branchtree.ProbeVertex;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
class PinAgent extends Agent {

    // Is a fuzzing Progress Running?
    protected boolean running = false;
    // StartTime of the last Fuzzing Vektor
    protected long startTime;
    // StopTime of the last Fuzzing Vektor
    protected long stopTime;
    // If the Application did Timeout
    protected boolean timeout;
    // If the Application did Crash
    protected boolean crash;
    private final String prefix = "PIN/pin.sh -log_inline -injection child -t PinScripts/obj-intel64/MyPinTool.so -o [output]/[id] -- ";
    private static final Logger LOG = Logger.getLogger(PinAgent.class.getName());

    /**
     * Default Constructor
     */
    public PinAgent() {
	timeout = false;
	crash = false;

    }

    @Override
    public void applicationStart(TLSServer server) {
	if (running) {
	    throw new IllegalStateException("Cannot start a running PIN Agent");
	}
	startTime = System.currentTimeMillis();
	running = true;
	server.start(prefix);
    }

    @Override
    public void applicationStop(TLSServer server) {
	if (!running) {
	    throw new IllegalStateException("Cannot stop a stopped PIN Agent");
	}
	stopTime = System.currentTimeMillis();
	running = false;
    }

    @Override
    public Result collectResults(File branchTrace, WorkflowTrace trace, WorkflowTrace executedTrace) {
	if (running) {
	    throw new IllegalStateException("Can't collect Results, Agent still running!");
	}

	String tail = tail(branchTrace);
	if (tail.startsWith("S")) {
	    LOG.log(Level.INFO, "Found a Crash!");
	    crash = true;
	}
	DirectedGraph<ProbeVertex, CountEdge> graph = new DefaultDirectedGraph<>(CountEdge.class);
	HashMap<Long, ProbeVertex> map = new HashMap<>();
	try {

	    try (BufferedReader br = new BufferedReader(new FileReader(branchTrace))) {

		String line = br.readLine();
		while ((line = br.readLine()) != null) {
		    String[] split = line.split("\\s+");
		    // TODO nur notlösung
		    long src;
		    if (split[0].equals("0xffffffffffffffff")) {
			src = Long.MAX_VALUE;
		    } else {
			src = Long.parseLong(split[0].substring(2), 16);
		    }
		    long dst;
		    if (split[1].equals("0xffffffffffffffff")) {
			dst = Long.MAX_VALUE;
		    } else {
			dst = Long.parseLong(split[1].substring(2), 16);
		    }
		    int count = Integer.parseInt(split[3]);
		    ProbeVertex source = map.get(src);
		    if (source == null) {
			source = new ProbeVertex(src);
			graph.addVertex(source);
			map.put(src, source);
		    }
		    ProbeVertex destination = map.get(dst);
		    if (destination == null) {
			destination = new ProbeVertex(dst);
			graph.addVertex(destination);
			map.put(dst, destination);
		    }

		    CountEdge edge = graph.getEdge(new ProbeVertex(src), new ProbeVertex(dst));
		    if (edge == null) {
			edge = graph.addEdge(source, destination);
		    }
		    edge.add(count);

		}
	    }
	} catch (IOException ex) {
	    Logger.getLogger(PinAgent.class.getName()).log(Level.SEVERE, null, ex);
	}
	BranchTrace t = new BranchTrace(graph);
	Result result = new Result(crash, timeout, startTime, stopTime, t, trace, executedTrace, LogFileIDManager
		.getInstance().getFilename());

	return result;
    }

    private String tail(File file) {
	RandomAccessFile fileHandler = null;
	try {
	    fileHandler = new RandomAccessFile(file, "r");
	    long fileLength = fileHandler.length() - 1;
	    StringBuilder sb = new StringBuilder();

	    for (long filePointer = fileLength; filePointer != -1; filePointer--) {
		fileHandler.seek(filePointer);
		int readByte = fileHandler.readByte();

		if (readByte == 0xA) {
		    if (filePointer == fileLength) {
			continue;
		    }
		    break;

		} else if (readByte == 0xD) {
		    if (filePointer == fileLength - 1) {
			continue;
		    }
		    break;
		}

		sb.append((char) readByte);
	    }

	    String lastLine = sb.reverse().toString();
	    return lastLine;
	} catch (java.io.FileNotFoundException e) {
	    e.printStackTrace();
	    return null;
	} catch (java.io.IOException e) {
	    e.printStackTrace();
	    return null;
	} finally {
	    if (fileHandler != null) {
		try {
		    fileHandler.close();
		} catch (IOException e) {
		    /* ignore */
		}
	    }
	}
    }

}
