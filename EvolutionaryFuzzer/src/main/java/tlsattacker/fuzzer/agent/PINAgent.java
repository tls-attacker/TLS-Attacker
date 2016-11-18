/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.helper.LogFileIDManager;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.testvector.TestVector;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;

/**
 * An Agent implemented with dynamic instrumentation with the aid of Intels Pin
 * tool.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PINAgent extends Agent {

    /**
     * The name of the Agent when referred by command line
     */
    public static final String optionName = "PIN";

    /**
     * Parses the readers contents into a BranchTrace object
     * 
     * @param bufferedReader
     * @return A newly generated BranchTrace object
     */
    private static BranchTrace getBranchTrace(BufferedReader bufferedReader) {
        try {
            Set<Long> verticesSet = new HashSet<>();
            Map<Edge, Edge> edgeMap = new HashMap<>();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                try {
                    if (line.isEmpty()) {
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

    /**
     * The prefix that has to be set in front of the actual server command
     */
    private final String prefix;

    /**
     * Config object used
     */
    private FuzzerGeneralConfig config;

    /**
     * Default Constructor
     * 
     * @param keypair
     */
    public PINAgent(FuzzerGeneralConfig config, ServerCertificateStructure keypair, TLSServer server) {
        super(keypair, server);
        this.config = config;

        timeout = false;
        crash = false;
        // TODO put into config File
        if (config.getInjectPinChild()) {
            prefix = "PIN/pin -log_inline -injection child -t PinScripts/obj-intel64/MyPinTool.so -o [output]/[id] -- ";
        } else {
            prefix = "PIN/pin -log_inline -t PinScripts/obj-intel64/MyPinTool.so -o [output]/[id] -- ";
        }
    }

    @Override
    public void applicationStart() {
        if (running) {
            throw new IllegalStateException("Cannot start a running PIN Agent");
        }
        startTime = System.currentTimeMillis();
        running = true;
        server.start(prefix, keypair.getCertificateFile(), keypair.getKeyFile());
    }

    @Override
    public void applicationStop() {
        if (!running) {
            throw new IllegalStateException("Cannot stop a stopped PIN Agent");
        }
        stopTime = System.currentTimeMillis();
        running = false;
        server.stop();
    }

    @Override
    public AgentResult collectResults(File branchTrace, TestVector vector) {
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
                LOG.log(Level.INFO, "Found a crash:{0}", line);
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

        AgentResult result = new AgentResult(crash, timeout, startTime, stopTime, t, vector, LogFileIDManager
                .getInstance().getFilename(), server);

        return result;
    }

    private static final Logger LOG = Logger.getLogger(PINAgent.class.getName());
}
