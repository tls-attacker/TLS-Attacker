/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Main;

import Config.ConfigManager;
import Server.ServerManager;
import Controller.FuzzerController;
import Executor.DebugExecutor;
import Controller.Controller;
import Config.EvolutionaryFuzzerConfig;
import Helper.Cleaner;
import WorkFlowType.WorkFlowTraceType;
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

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main {

    private static final Logger LOG = Logger.getLogger(Main.class.getName());

    /**
     * 
     * @param args
     */
    public static void main(String args[]) {
	// TODO write a console interface
	GeneralConfig generalConfig = new GeneralConfig();

	EvolutionaryFuzzerConfig evoConfig = ConfigManager.getInstance().getConfig();
	JCommander jc = new JCommander(evoConfig);
	jc.addCommand(EvolutionaryFuzzerConfig.ATTACK_COMMAND, evoConfig);
	jc.addCommand("tracetypes", new Object());
	jc.addCommand("clean", new Object());
	jc.addCommand("clean-all", new Object());
	jc.addCommand("execute-faulty", new Object());
	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	switch (jc.getParsedCommand()) {
	    case EvolutionaryFuzzerConfig.ATTACK_COMMAND:
		Controller controller = new FuzzerController(evoConfig);
		controller.startFuzzer();
		controller.startConsoleInput();
		break;
	    case "tracetypes":
		File f = new File(evoConfig.getOutputFolder() + "uniqueFlows/");
		List<WorkflowTrace> traces = WorkflowTraceSerializer.readFolder(f);

		LOG.log(Level.INFO, "Fininshed reading.");
		Set<WorkFlowTraceType> set = WorkflowTraceTypeManager.generateTypeList(traces);

		LOG.log(Level.INFO, "Found " + set.size() + " different TraceTypes");

		set = WorkflowTraceTypeManager.generateCleanTypeList(traces);

		LOG.log(Level.INFO, "Found " + set.size() + " different clean TraceTypes");
		for (WorkFlowTraceType type : set) {
		    System.out.println(type);
		}
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
		traces = WorkflowTraceSerializer.readFolder(f);
		for (WorkflowTrace trace : traces) {
		    LOG.log(Level.INFO, "Trace:" + trace.getName());
		    DebugExecutor.execute(trace);
		}
		break;

	    default:
		jc.usage();
		return;
	}
    }
}
