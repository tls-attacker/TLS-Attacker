/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.main;

import tlsattacker.fuzzer.calibration.TimeoutCalibrator;
import tlsattacker.fuzzer.config.CalibrationConfig;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.controller.CommandLineController;
import tlsattacker.fuzzer.executor.DebugExecutor;
import tlsattacker.fuzzer.controller.Controller;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.ExecuteFaultyConfig;
import tlsattacker.fuzzer.config.ServerConfig;
import tlsattacker.fuzzer.config.TraceTypesConfig;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.flowui.GraphWindow;
import tlsattacker.fuzzer.server.ServerSerializer;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import tlsattacker.fuzzer.workflow.MessageFlow;
import tlsattacker.fuzzer.workflow.WorkflowGraphBuilder;
import tlsattacker.fuzzer.workflow.WorkflowTraceType;
import tlsattacker.fuzzer.workflow.WorkflowTraceTypeManager;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.graph.DirectedMultigraph;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;
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
        TraceTypesConfig traceTypesConfig = new TraceTypesConfig();
        ExecuteFaultyConfig faultyConfig = new ExecuteFaultyConfig();
        CalibrationConfig calibrationConfig = new CalibrationConfig();
        JCommander jc = new JCommander(generalConfig);
        jc.addCommand(EvolutionaryFuzzerConfig.ATTACK_COMMAND, evoConfig);
        jc.addCommand("tracetypes", traceTypesConfig);
        jc.addCommand("execute-faulty", faultyConfig);
        jc.addCommand("new-server", serverConfig);
        jc.addCommand("calibrate", calibrationConfig);
        jc.addCommand("test-certificates", evoConfig);
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
                    Controller controller = new CommandLineController(evoConfig);
                    controller.startFuzzer();
                    controller.startInterface();
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
                File f = new File(traceTypesConfig.getTraceTypesFolder());
                if (f.exists() && f.isDirectory())
                {
                    List<TestVector> vectors = TestVectorSerializer.readFolder(f);

                    LOG.log(Level.INFO, "Fininshed reading.");
                    Set<WorkflowTraceType> set = WorkflowTraceTypeManager.generateTypeList(vectors,
                            ConnectionEnd.CLIENT);

                    LOG.log(Level.INFO, "Found " + set.size() + " different TraceTypes");

                    set = WorkflowTraceTypeManager.generateCleanTypeList(vectors, ConnectionEnd.CLIENT);

                    LOG.log(Level.INFO, "Found " + set.size() + " different clean TraceTypes");
                    // AutomataWindow.showWindow(WorkflowAutomataBuilder.generateWorkflowAutomata(set));
                    DirectedMultigraph<Integer, MessageFlow> graph = WorkflowGraphBuilder.generateWorkflowGraph(set);
                    GraphWindow.showWindow(graph);
                }
                else
                {
                    LOG.log(Level.INFO, "The Specified Folder does not exist or is not a Folder:" + f.getAbsolutePath());
                }
                break;
            case "execute-faulty":
                ServerManager manager = ServerManager.getInstance();
                manager.init(evoConfig);
                f = new File(evoConfig.getOutputFaultyFolder());
                List<TestVector> vectors = TestVectorSerializer.readFolder(f);
                for (TestVector vector : vectors)
                {
                    LOG.log(Level.INFO, "Trace:" + vector.getTrace().getName());
                    DebugExecutor.execute(vector, evoConfig);
                }
                break;
            case "new-server":
                TLSServer server = new TLSServer(serverConfig.getIp(), serverConfig.getPort(),
                        serverConfig.getStartcommand(), serverConfig.getAccept());
                {
                    try
                    {
                        ServerSerializer.write(server, new File(serverConfig.getOutput()));
                        LOG.log(Level.INFO, "Wrote Server to:" + new File(serverConfig.getOutput()).getAbsolutePath());
                    }
                    catch (Exception ex)
                    {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, "Could not write Server to file!", ex);
                    }
                }
                break;
            case "calibrate":
                TimeoutCalibrator calibrator = new TimeoutCalibrator(calibrationConfig);
                calibrator.setGainFactor(calibrationConfig.getGain());
                calibrator.setLimit(calibrationConfig.getTimeoutLimit());
                ServerManager.getInstance().init(calibrationConfig);
                int timeout = calibrator.calibrateTimeout();
                LOG.log(Level.INFO, "Recommended Timeout for this Server is:" + timeout);
                break;
            case "test-certificates":
                ServerManager.getInstance().init(calibrationConfig);
                FixedCertificateMutator mutator = new FixedCertificateMutator();
                mutator.selfTest();
                break;
            default:
                jc.usage();
                return;
        }

    }
}
