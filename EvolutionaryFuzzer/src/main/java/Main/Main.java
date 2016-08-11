/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Main;

import Automata.WorkflowAutomataBuilder;
import Config.ConfigManager;
import Server.ServerManager;
import Controller.FuzzerController;
import Executor.DebugExecutor;
import Controller.Controller;
import Config.EvolutionaryFuzzerConfig;
import Config.ServerConfig;
import Exceptions.IllegalCertificateMutatorException;
import Exceptions.IllegalMutatorException;
import FlowVisualisation.AutomataWindow;
import FlowVisualisation.GraphWindow;
import Helper.Cleaner;
import Server.ServerSerializer;
import Server.TLSServer;
import TestVector.TestVector;
import TestVector.TestVectorSerializer;
import WorkFlowType.MessageFlow;
import WorkFlowType.WorkflowGraphBuilder;
import WorkFlowType.WorkflowTraceType;
import WorkFlowType.WorkflowTraceTypeManager;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DirectedMultigraph;
import org.jgrapht.graph.ListenableDirectedGraph;
import weka.core.Utils;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main
{

    private static final Logger LOG = Logger.getLogger(Main.class.getName());

    /**
     *
     * @param args
     */
    public static void main(String args[])
    {
        LOG.log(Level.FINE, Utils.arrayToString(args));
        GeneralConfig generalConfig = new GeneralConfig();

        EvolutionaryFuzzerConfig evoConfig = ConfigManager.getInstance().getConfig();
        ServerConfig serverConfig = new ServerConfig();
        JCommander jc = new JCommander(generalConfig);
        jc.addCommand(EvolutionaryFuzzerConfig.ATTACK_COMMAND, evoConfig);
        jc.addCommand("tracetypes", evoConfig);
        jc.addCommand("clean", evoConfig);
        jc.addCommand("clean-all", evoConfig);
        jc.addCommand("execute-faulty", evoConfig);
        jc.addCommand("new-server", serverConfig);
        // TODO Configs cleanup
        try
        {
            jc.parse(args);
            if (generalConfig.isHelp() || jc.getParsedCommand() == null)
            {
                jc.usage();
                return;
            }
        }
        catch (Exception E)
        {
            LOG.log(Level.FINE, E.getLocalizedMessage(), E);
            jc.usage();
            return;
        }

        switch (jc.getParsedCommand())
        {
            case EvolutionaryFuzzerConfig.ATTACK_COMMAND:
                try
                {
                    Controller controller = new FuzzerController(evoConfig);
                    controller.startFuzzer();
                    controller.startConsoleInput();
                }
                catch (IllegalCertificateMutatorException ex)
                {
                    LOG.info("Unknown Certificate Mutator. Aborting...");
                }
                catch (IllegalMutatorException ex)
                {
                    LOG.info("Unknown Mutator. Aborting...");
                }
                break;
            case "tracetypes":
                File f = new File(evoConfig.getOutputFolder() + "uniqueFlows/");
                List<TestVector> vectors = TestVectorSerializer.readFolder(f);

                LOG.log(Level.INFO, "Fininshed reading.");
                Set<WorkflowTraceType> set = WorkflowTraceTypeManager.generateTypeList(vectors);

                LOG.log(Level.INFO, "Found " + set.size() + " different TraceTypes");

                set = WorkflowTraceTypeManager.generateCleanTypeList(vectors);

                LOG.log(Level.INFO, "Found " + set.size() + " different clean TraceTypes");
                // AutomataWindow.showWindow(WorkflowAutomataBuilder.generateWorkflowAutomata(set));
                DirectedMultigraph<Integer, MessageFlow> graph = WorkflowGraphBuilder.generateWorkflowGraph(set);
                GraphWindow.showWindow(graph);
                break;
            case "clean":
                Cleaner.cleanTraces(evoConfig);
                break;
            case "clean-all":
                Cleaner.cleanAll(evoConfig);
                break;
            case "execute-faulty":
                ServerManager manager = ServerManager.getInstance();
                manager.init(evoConfig);
                f = new File(evoConfig.getOutputFolder() + "faulty/");
                vectors = TestVectorSerializer.readFolder(f);
                for (TestVector vector : vectors)
                {
                    LOG.log(Level.INFO, "Trace:" + vector.getTrace().getName());
                    DebugExecutor.execute(vector, evoConfig);
                }
                break;
            case "new-server":
                TLSServer server = new TLSServer(serverConfig.getIp(), serverConfig.getPort(), serverConfig.getStartcommand(), serverConfig.getAccept());
                {
                    try
                    {
                        ServerSerializer.write(server, new File(serverConfig.getOutput()));
                        LOG.log(Level.INFO, "Wrote Server to:"+new File(serverConfig.getOutput()).getAbsolutePath());
                    }
                    catch (Exception ex)
                    {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, "Could not write Server to file!", ex);
                    }
                }
                break;
            default:
                jc.usage();
                return;
        }

    }
}
