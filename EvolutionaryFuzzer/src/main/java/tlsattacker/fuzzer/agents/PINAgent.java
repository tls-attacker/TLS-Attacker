/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.testvector.TestVector;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An Agent implemented with dynamic instrumentation with the aid of Intels Pin tool. 
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PINAgent extends Agent {

    private static final Logger LOG = Logger.getLogger(PINAgent.class.getName());

    public static final String optionName = "PIN";

    private static BranchTrace getBranchTrace(BufferedReader br)
    {
        try {
            Set<Long> verticesSet = new HashSet<>();
            Map<Edge, Edge> edgeMap = new HashMap<>();
            String line;
            while ((line = br.readLine()) != null) {
                try {
                    if (line.equals("")) {
                        continue;
                    }
                    String[] split = line.split("\\s+");
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
                    verticesSet.add(src);
                    verticesSet.add(dst);
                    Edge e = new Edge(src, dst);
                    e.setCounter(count);
                    edgeMap.put(e, e);
                } catch (Exception E) {
                    E.printStackTrace();
                }
            }
            return new BranchTrace(verticesSet, edgeMap);
            
        } catch (IOException ex) {
            Logger.getLogger(PINAgent.class.getName()).log(Level.SEVERE,
                    "Could not create BranchTrace object From File! Creating empty BranchTrace instead!", ex);
        }
        return new BranchTrace();
    }
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
    private final String prefix;

    /**
     * Default Constructor
     */
    public PINAgent(ServerCertificateStructure keypair) {
	super(keypair);
	timeout = false;
	crash = false;
	if (ConfigManager.getInstance().getConfig().getInjectPinChild()) {
	    prefix = "PIN/pin -log_inline -injection child -t PinScripts/obj-intel64/MyPinTool.so -o [output]/[id] -- ";
	} else {
	    prefix = "PIN/pin -log_inline -t PinScripts/obj-intel64/MyPinTool.so -o [output]/[id] -- ";
	}
    }

    @Override
    public void applicationStart(TLSServer server) {
	if (running) {
	    throw new IllegalStateException("Cannot start a running PIN Agent");
	}
	startTime = System.currentTimeMillis();
	running = true;
	server.start(prefix, keypair.getCertificateFile(), keypair.getKeyFile());
    }

    @Override
    public void applicationStop(TLSServer server) {
	if (!running) {
	    throw new IllegalStateException("Cannot stop a stopped PIN Agent");
	}
	stopTime = System.currentTimeMillis();
	running = false;
	server.stop();
    }

    @Override
    public Result collectResults(File branchTrace, TestVector vector) {
	if (running) {
	    throw new IllegalStateException("Can't collect Results, Agent still running!");
	}
	BranchTrace t = null;
	try {
	    BufferedReader br = new BufferedReader(new FileReader(branchTrace));

	    String line = br.readLine();

	    if (line != null
		    && (line.contains("SIGSEV") || line.contains("SIGILL") || line.contains("SIGSYS")
			    || line.contains("SIGABRT") || line.contains("SIGCHLD") || line.contains("SIGFPE") || line
				.contains("SIGALRM"))) {
		crash = true;
		LOG.log(Level.INFO, "Found a crash:" + line);
		// Skip 2 lines
		line = br.readLine();
		line = br.readLine();

	    }
	    t = getBranchTrace(br);
	    br.close();

	} catch (IOException ex) {
	    Logger.getLogger(PINAgent.class.getName()).log(Level.SEVERE, null, ex);
	    ex.printStackTrace();
	}

	Result result = new Result(crash, timeout, startTime, stopTime, t, vector, LogFileIDManager.getInstance()
		.getFilename());

	return result;
    }


}
