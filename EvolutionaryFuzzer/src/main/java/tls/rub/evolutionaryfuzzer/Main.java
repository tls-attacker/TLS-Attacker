/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import WorkFlowType.WorkFlowTraceType;
import WorkFlowType.WorkflowTraceTypeManager;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

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
        //TODO write a console interface
        GeneralConfig generalConfig = new GeneralConfig();

        EvolutionaryFuzzerConfig evoConfig = new EvolutionaryFuzzerConfig();
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
                break;
            case "tracetypes":
                File f = new File(evoConfig.getOutputFolder() + "good/");
                ArrayList<WorkflowTrace> list = new ArrayList<>();
                LOG.log(Level.INFO, "Reading good Traces in:");

                for (File file : f.listFiles()) {
                    if (file.getName().startsWith(".")) {
                        //We ignore the .gitignore File
                        continue;
                    }
                    try {

                        WorkflowTrace trace = WorkflowTraceSerializer.read(new FileInputStream(file));
                        list.add(trace);
                    } catch (JAXBException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (IOException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (XMLStreamException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (Throwable E) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), E);

                    }
                }
                LOG.log(Level.INFO, "Fininshed reading.");
                Set<WorkFlowTraceType> set = WorkflowTraceTypeManager.generateTypeList(list);

                LOG.log(Level.INFO, "Found " + set.size() + " different TraceTypes");
                for (WorkFlowTraceType type : set) {
                    System.out.println(type);
                }
                set = WorkflowTraceTypeManager.generateCleanTypeList(list);

                LOG.log(Level.INFO, "Found " + set.size() + " different clean TraceTypes");
                for (WorkFlowTraceType type : set) {
                    System.out.println(type);
                }
                break;
            case "clean":
                break;
            case "clean-all":
                break;
            case "execute-faulty":
                ServerManager manager = ServerManager.getInstance();
                manager.init(evoConfig);
                f = new File(evoConfig.getOutputFolder() + "faulty/");
                
                for (File file : f.listFiles()) {
                    if (file.getName().startsWith(".")) {
                        //We ignore the .gitignore File
                        continue;
                    }
                    try {

                        WorkflowTrace trace = WorkflowTraceSerializer.read(new FileInputStream(file));
                        LOG.log(Level.INFO, "Trace:"+file.getAbsolutePath());
                        DebugExecutor.execute(trace);
                    } catch (JAXBException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (IOException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (XMLStreamException ex) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
                    } catch (Throwable E) {
                        Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), E);

                    }
                }

                break;

            default:
                jc.usage();
                return;
        }
    }
}
