package Controller;

import Executor.ExecutorThreadPool;
import Mutator.Mutator;
import Controller.Controller;
import Config.EvolutionaryFuzzerConfig;
import Graphs.CountEdge;
import Graphs.ProbeVertex;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import Result.ResultContainer;
import Server.ServerManager;
import Mutator.SimpleMutator;
import Server.TLSServer;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Set;
import org.jgrapht.DirectedGraph;

/**
 * Currently only Implementation of the Controller Interface which controls the
 * complete executions
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerController extends Controller {

    private static final Logger LOG = Logger.getLogger(FuzzerController.class.getName());

    // Chosen Mutator
    private final Mutator mutator;
    // ThreadPool to start or stop
    private final ExecutorThreadPool pool;

    /**
     * Basic Constructor, initializes the Server List, generates the necessary
     * Config Files and Contexts and also commints to a mutation Engine
     * 
     * @param config
     *            Configuration used by the Controller
     */
    public FuzzerController(EvolutionaryFuzzerConfig config) {
	super(config);
	ServerManager serverManager = ServerManager.getInstance();
	serverManager.init(config);

	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	TlsContext tmpTlsContext = configHandler.initializeTlsContext(new EvolutionaryFuzzerConfig());
	mutator = new SimpleMutator(tmpTlsContext, config);
	int threads = config.getThreads();
	if (threads == -1) {
	    threads = serverManager.getNumberOfServers();
	}
	pool = new ExecutorThreadPool(threads, mutator, config);
	Thread t = new Thread(pool);
	t.setName("Executor Thread Pool");
	t.start();
    }

    /**
     * Starts the Fuzzer
     */
    @Override
    public void startFuzzer() {
	this.isRunning = false;
	pool.setStopped(false);
    }

    /**
     * Stops the Fuzzer
     */
    @Override
    public void stopFuzzer() {
	this.isRunning = false;
	pool.setStopped(true);
    }

    @Override
    public void startConsoleInput() {
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	while (true) {
	    String s = null;
	    try {
		System.out.print(">");
		s = br.readLine();
	    } catch (IOException ex) {
		Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
	    }
	    switch (s) {
		case "start":
		    startFuzzer();
		    break;
		case "stop":
		    stopFuzzer();
		    break;
		case "status":
		    ResultContainer con = ResultContainer.getInstance();
		    int goodTraces = con.getGoodTraces().size();
		    int hitVertices = con.getBranch().getVerticesCount();
		    int hitBranches = con.getBranch().getBranchCount();
		    System.out
			    .println("Traces succesful executed:" + ResultContainer.getInstance().getResults().size());
		    System.out.println("Crashed:" + con.getCrashedCount() + " Timeout:" + con.getTimeoutCount()
			    + " WorkflowTypes:" + con.getTypeCount());
		    System.out.println("Good Traces:" + goodTraces + " Hit Vertices:" + hitVertices + " Hit Branches:"
			    + hitBranches);
		    System.out.println("Servers:" + ServerManager.getInstance().getServerCount() + " Currently Free:"
			    + ServerManager.getInstance().getFreeServerCount());
		    break;
		case "server":
		    List<TLSServer> serverList = ServerManager.getInstance().getAllServers();
		    for (TLSServer server : serverList) {
			System.out.println(server);
		    }
		    break;
		case "edges":
		    LOG.log(Level.INFO, "Dumping Edge Information to edges.dump");
		    try {
			Thread.sleep(1000);
		    } catch (InterruptedException ex) {
			Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
		    }

		    DirectedGraph<ProbeVertex, CountEdge> graph = ResultContainer.getInstance().getBranch().getGraph();
		    PrintWriter writer;
		    try {
			writer = new PrintWriter("edges.dump", "UTF-8");
			Set<CountEdge> set = graph.edgeSet();
			for (CountEdge edge : set) {
			    writer.println(graph.getEdgeSource(edge).getProbeID() + " "
				    + graph.getEdgeTarget(edge).getProbeID());
			}
			writer.close();
		    } catch (FileNotFoundException ex) {
			Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
		    } catch (UnsupportedEncodingException ex) {
			Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
		    }
		    LOG.log(Level.INFO, "Dump finished");

		    break;
		case "vertices":
		    LOG.log(Level.INFO, "Dumping Vertex Information to vertices.dump");
		    graph = ResultContainer.getInstance().getBranch().getGraph();
		    writer = null;
		    try {
			writer = new PrintWriter("vertices.dump", "UTF-8");
			Set<ProbeVertex> set = graph.vertexSet();
			for (ProbeVertex vertex : set) {
			    writer.println(vertex.getProbeID());
			}
			writer.close();
		    } catch (FileNotFoundException ex) {
			Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
		    } catch (UnsupportedEncodingException ex) {
			Logger.getLogger(FuzzerController.class.getName()).log(Level.SEVERE, null, ex);
		    }
		    LOG.log(Level.INFO, "Dump finished");

		    break;
		default:
		    System.out.println("Commands: start, stop, status, server, edges, vertices");
		    break;
	    }
	}
    }

}
