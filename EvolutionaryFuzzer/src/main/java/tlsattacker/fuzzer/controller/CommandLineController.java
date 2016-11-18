/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import tlsattacker.fuzzer.analyzer.rules.IsGoodRule;
import tlsattacker.fuzzer.executor.ExecutorThreadPool;
import tlsattacker.fuzzer.mutator.Mutator;
import tlsattacker.fuzzer.controller.Controller;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutatorFactory;
import tlsattacker.fuzzer.mutator.MutatorFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.Set;
import tlsattacker.fuzzer.analyzer.Analyzer;
import tlsattacker.fuzzer.analyzer.AnalyzerFactory;
import tlsattacker.fuzzer.analyzer.AnalyzerThread;
import tlsattacker.fuzzer.analyzer.RuleAnalyzer;
import tlsattacker.fuzzer.exceptions.FuzzerConfigurationException;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;

/**
 * Currently only Implementation of the Controller Interface which controls the
 * the fuzzer with a commandline interface.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CommandLineController extends Controller {

    /**
     * The name of the Controller when referred by command line
     */
    public static final String optionName = "commandline";

    /**
     * Chosen Mutator
     */
    protected final Mutator mutator;

    /**
     * Chosen CertificateMutator
     */
    protected final CertificateMutator certMutator;

    /**
     * The used ThreadPool for the fuzzer
     */
    protected final ExecutorThreadPool pool;

    /**
     * Analyzer to use
     */
    protected final Analyzer analyzer;

    /**
     * Thread that manages the thread pool
     */
    protected final Thread poolThread;

    /**
     * Thread that analyzes the results
     */
    protected AnalyzerThread analyzerThread;

    /**
     * Basic Constructor, initializes the Server List, generates the necessary
     * Config Files and Contexts and also commints to a mutation Engine
     * 
     * @param config
     *            Configuration used by the Controller
     * @throws tlsattacker.fuzzer.exceptions.IllegalMutatorException
     * @throws tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException
     * @throws tlsattacker.fuzzer.exceptions.IllegalAnalyzerException
     * @throws tlsattacker.fuzzer.exceptions.FuzzerConfigurationException
     */
    public CommandLineController(EvolutionaryFuzzerConfig config) throws IllegalMutatorException,
            IllegalCertificateMutatorException, IllegalAnalyzerException, FuzzerConfigurationException {
        super(config);
        analyzer = AnalyzerFactory.getAnalyzer(config);
        certMutator = CertificateMutatorFactory.getCertificateMutator(config);
        mutator = MutatorFactory.getMutator(certMutator, config);
        int threads = config.getThreads();
        if (threads == -1) {
            threads = ServerManager.getInstance().getNumberOfServers();
        }
        analyzerThread = new AnalyzerThread(analyzer);
        analyzerThread.setName("Analyzer Thread");
        pool = new ExecutorThreadPool(threads, mutator, config, analyzerThread);
        poolThread = new Thread(pool);
        poolThread.setName("Executor Thread Pool");
    }

    public void start() {
        analyzerThread.start();
        poolThread.start();
    }

    /**
     * Starts the Fuzzer
     */
    @Override
    public void startFuzzer() {
        this.isRunning = true;
        pool.setStopped(false);
    }

    /**
     * Stops the Fuzzer
     */
    @Override
    public void stopFuzzer() {
        LOG.log(Level.INFO, "Stopping Fuzzer!");
        this.isRunning = false;
        pool.setStopped(true);
        do {
            try {
                Thread.sleep(50);
            } catch (InterruptedException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } while (pool.hasRunningThreads());
        LOG.log(Level.INFO, "Fuzzer stopped!");
    }

    public void printServerStatus() {
        List<TLSServer> serverList = ServerManager.getInstance().getAllServers();
        for (TLSServer server : serverList) {
            System.out.println(server);
        }
    }

    public void dumpEdges(String split[]) {
        String file = "edges.dump";
        if (split.length == 2) {
            file = split[1];
        }
        LOG.log(Level.INFO, "Dumping Edge Information to {0}", file);
        stopFuzzer();
        do {
            try {
                Thread.sleep(50);
            } catch (InterruptedException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } while (pool.hasRunningThreads());

        BranchTrace trace = analyzer.getBranchTrace();
        PrintWriter writer;
        try {
            writer = new PrintWriter(file, "UTF-8");
            Map<Edge, Edge> set = trace.getEdgeMap();
            for (Edge edge : set.values()) {
                writer.println(edge.getSource() + " " + edge.getDestination());
            }
            writer.close();
        } catch (FileNotFoundException | UnsupportedEncodingException ex) {
            Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
        }
        LOG.log(Level.INFO, "Dump finished");
        startFuzzer();
    }

    public void dumpVertices(String[] split) {
        String file = "vertices.dump";
        if (split.length == 2) {
            file = split[1];
        }
        LOG.log(Level.INFO, "Dumping Vertex Information to {0}", file);
        stopFuzzer();
        do {
            try {
                Thread.sleep(50);
            } catch (InterruptedException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } while (pool.hasRunningThreads());

        BranchTrace trace = analyzer.getBranchTrace();
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(file, "UTF-8");
            Set<Long> set = trace.getVerticesSet();
            for (Long vertex : set) {
                writer.println(vertex);
            }
            writer.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
        }
        LOG.log(Level.INFO, "Dump finished");
        startFuzzer();
    }

    public void loadGraph(String[] split) {
        BranchTrace trace = analyzer.getBranchTrace();
        if (split.length != 2) {
            LOG.log(Level.INFO, "You need to specify a File to load");
        } else {
            String file = split[1];
            LOG.log(Level.INFO, "Loading from:{0}", file);
            ObjectInputStream objectinputstream = null;
            try {
                FileInputStream streamIn = new FileInputStream(file);
                objectinputstream = new ObjectInputStream(streamIn);
                BranchTrace tempTrace = (BranchTrace) objectinputstream.readObject();
                trace.merge(tempTrace);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (objectinputstream != null) {
                    try {
                        objectinputstream.close();
                    } catch (IOException ex) {
                        Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
    }

    public void saveGraph(String split[]) {
        BranchTrace trace = analyzer.getBranchTrace();
        if (split.length != 2) {
            LOG.log(Level.INFO, "You need to specify a File to Save to");
        } else {
            String file = split[1];
            LOG.log(Level.INFO, "Saving to:{0}", file);
            FileOutputStream fout = null;
            ObjectOutputStream oos = null;
            try {
                fout = new FileOutputStream(file);
                oos = new ObjectOutputStream(fout);
                oos.writeObject(trace);

            } catch (FileNotFoundException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                if (fout != null) {
                    try {
                        fout.close();
                    } catch (IOException ex) {
                        Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                if (oos != null) {
                    try {
                        oos.close();
                    } catch (IOException ex) {
                        Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
    }

    public void printUsage() {
        System.out
                .println("Commands: start, stop, status, server, edges <file>, vertices <file>, loadGraph <file>, saveGraph <file>");

    }

    public void printStatus() {
        System.out.println(analyzer.getReport());
    }

    /**
     * Starts the commandline interface
     */
    @Override
    public void startInterface() {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            String s = null;
            try {
                System.out.print(">");
                s = br.readLine();
            } catch (IOException ex) {
                Logger.getLogger(CommandLineController.class.getName()).log(Level.SEVERE, null, ex);
            }
            String[] split = s.split(" ");
            if (split.length > 0) {
                switch (split[0]) {
                    case "start":
                        startFuzzer();
                        break;
                    case "stop":
                        stopFuzzer();
                        break;
                    case "status":
                        printStatus();
                        break;
                    case "server":
                        printServerStatus();
                        break;
                    case "edges":
                        dumpEdges(split);
                        break;
                    case "vertices":
                        dumpVertices(split);
                        break;
                    case "loadGraph":
                        loadGraph(split);
                        break;
                    case "saveGraph":
                        saveGraph(split);
                        break;
                    default:
                        printUsage();
                        break;
                }
            }
        }
    }

    private static final Logger LOG = Logger.getLogger(CommandLineController.class.getName());
}
