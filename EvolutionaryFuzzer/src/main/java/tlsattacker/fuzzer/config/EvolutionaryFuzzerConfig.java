package tlsattacker.fuzzer.config;

import tlsattacker.fuzzer.config.mutator.ActionExecutorTypeConfig;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.beust.jcommander.validators.PositiveInteger;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import java.io.File;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import tlsattacker.fuzzer.controller.CommandLineController;
import tlsattacker.fuzzer.mutator.NoneMutator;
import tlsattacker.fuzzer.mutator.SimpleMutator;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;

/**
 * A Config class which controlls the behavior of the fuzzer
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@Parameters(commandDescription = "Starts the Fuzzer")
public class EvolutionaryFuzzerConfig extends FuzzerGeneralConfig {

    /**
     * The name of the command which uses this config
     */
    public static final String ATTACK_COMMAND = "fuzzer";

    /**
     * The general folder in which results should be saved
     */
    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.", converter = FileConverter.class)
    private String outputFolder = "./data/";

    /**
     * The folder which contains previously executed Testvectors which were
     * considered as good
     */
    @Parameter(names = "-archive_folder", description = "Archive Folder that contains TestVectors that should seed the Fuzzer", converter = FileConverter.class)
    private String archiveFolder = "./archive/";

    /**
     * Number of threads the Fuzzer should run, -1 means use as many as
     * configuration files are in the server config folder.
     */
    @Parameter(names = "-threads", description = "Number of Threads running Simultaniously, (Default:Number of Server in Config)", validateWith = PositiveInteger.class)
    private Integer threads = -1;

    /**
     * The mutator that should be used
     */
    @Parameter(names = "-mutator", description = "The Mutator the Fuzzer uses to generate new TestVectors. Possible: "
            + SimpleMutator.optionName + ", " + NoneMutator.optionName + "")
    private String mutator = SimpleMutator.optionName;

    /**
     * The controller that should be used
     */
    @Parameter(names = "-controller", description = "The Controller that is used to communicate with the Operator. Possible: "
            + CommandLineController.optionName)
    private String controller = CommandLineController.optionName;

    /**
     * The certificate mutator that should be used
     */
    @Parameter(names = "-certificate_mutator", description = "The Mutator the Fuzzer uses to generate new Certificates. Possible: "
            + FixedCertificateMutator.optionName)
    private String certMutator = "fixed";

    /**
     * If set true the archive folder is ignored
     */
    @Parameter(names = "-no_old", description = "The mutator wont run WorkflowTraces he finds in the Good WorkflowTrace Folder, before he starts generating new Mutations")
    private boolean noOld = false;

    /**
     * If set the server starts in a stopped state
     */
    @Parameter(names = "-start_stopped", description = "Starts the Fuzzer in a stopped state.")
    private boolean startStopped = false;

    /**
     * If set the fuzzer deletes all previously set recorded data
     */
    @Parameter(names = "-clean_start", description = "Deletes previous good Workflows on startup")
    private boolean cleanStart = false;

    /**
     * If set the PinAgent should inject into the child process TODO put in
     * agent config
     */
    @Parameter(names = "-inject_pin_child", description = "If the PIN Agent should instrument into the Childprocess")
    private final boolean injectPinChild = true;

    /**
     * If set the certificates should be tested for compatibility before
     * starting the fuzzer
     */
    @Parameter(names = "-certificate_mutator_selftest", description = "Test that the CertificateMutator is properly configured at start")
    private boolean certMutatorSelftest = false;

    /**
     * Timeout for server starts
     */
    @Parameter(names = "-boot_timeout", description = "The maximum time the fuzzer waits till the implementation boots up.")
    private Integer bootTimeout = 50000;

    /**
     * Temporary Folder which contains currently executed traces
     */
    private File tracesFolder;

    /**
     * The action executor config that should be used
     */
    private ActionExecutorTypeConfig actionExecutorConfig;
    // Are we currently in serialization mode?

    /**
     * If good testVectors should be serialized currently. This is useful if we
     * are executing archive vectors.
     */
    private boolean serialize = false;

    /**
     * Constructor for EvolutionaryFuzzerConfig, defaults output Folder to "."
     * and serverCommandFromFile to server/server.config
     */
    public EvolutionaryFuzzerConfig() {
        outputFolder = "data/";
        setFuzzingMode(true);
        setKeystore("../resources/rsa1024.jks");
        setPassword("password");
        setAlias("alias");
        this.tracesFolder = new File(outputFolder + "traces/");
        tracesFolder.mkdirs();
        new File(getOutputCertificateFolder()).mkdirs();
        new File(getOutputClientCertificateFolder()).mkdirs();
        new File(getOutputFolder()).mkdirs();
        new File(getOutputServerCertificateFolder()).mkdirs();
        new File(getCertificateMutatorConfigFolder()).mkdirs();
        new File(getAnalyzerConfigFolder()).mkdirs();
        new File(getOutputFaultyFolder()).mkdirs();
        new File(getArchiveFolder()).mkdirs();
        File f = new File(getMutatorConfigFolder() + "action_executor.conf");
        if (f.exists()) {
            actionExecutorConfig = JAXB.unmarshal(f, ActionExecutorTypeConfig.class);
        } else {
            actionExecutorConfig = new ActionExecutorTypeConfig();
            JAXB.marshal(actionExecutorConfig, f);
        }
    }

    public Integer getBootTimeout() {
        return bootTimeout;
    }

    public void setBootTimeout(Integer bootTimeout) {
        this.bootTimeout = bootTimeout;
    }

    public String getController() {
        return controller;
    }

    public void setController(String controller) {
        this.controller = controller;
    }

    public ActionExecutorTypeConfig getActionExecutorConfig() {
        return actionExecutorConfig;
    }

    public void setActionExecutorConfig(ActionExecutorTypeConfig actionExecutorConfig) {
        this.actionExecutorConfig = actionExecutorConfig;
    }

    public String getArchiveFolder() {
        return archiveFolder;
    }

    public void setArchiveFolder(String archiveFolder) {
        this.archiveFolder = archiveFolder;
    }

    public File getTracesFolder() {
        return tracesFolder;
    }

    public void setTracesFolder(File tracesFolder) {
        this.tracesFolder = tracesFolder;
    }

    public String getCertMutator() {
        return certMutator;
    }

    public void setCertMutator(String certMutator) {
        this.certMutator = certMutator;
    }

    public String getMutator() {
        return mutator;
    }

    public void setMutator(String mutator) {
        this.mutator = mutator;
    }

    public boolean isCleanStart() {
        return cleanStart;
    }

    public void setCleanStart(boolean cleanStart) {
        this.cleanStart = cleanStart;
    }

    public boolean isStartStopped() {
        return startStopped;
    }

    public void setStartStopped(boolean startStopped) {
        this.startStopped = startStopped;
    }

    public boolean isNoOld() {
        return noOld;
    }

    public void setNoOld(boolean noOld) {
        this.noOld = noOld;
    }

    public boolean isSerialize() {
        return serialize;
    }

    public void setSerialize(boolean serialize) {
        this.serialize = serialize;
    }

    public Integer getThreads() {
        return threads;
    }

    public void setThreads(Integer threads) {
        this.threads = threads;
    }

    public String getOutputFolder() {
        return outputFolder;
    }

    public String getOutputCertificateFolder() {
        return outputFolder + "certificates/";
    }

    public String getOutputClientCertificateFolder() {
        return configFolder + "certificates/client/";
    }

    public String getOutputServerCertificateFolder() {
        return configFolder + "certificates/server/";
    }

    public String getOutputFaultyFolder() {
        return outputFolder + "faulty/";
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
        File f = new File(outputFolder);
        f.mkdirs();
        this.tracesFolder = new File(outputFolder + "traces/");
        tracesFolder.mkdirs();// TODO check
        new File(getOutputFaultyFolder()).mkdirs();
        new File(getOutputClientCertificateFolder()).mkdirs();
        new File(getOutputCertificateFolder()).mkdirs();
        new File(getOutputServerCertificateFolder()).mkdirs();
    }

    public boolean getInjectPinChild() {
        return injectPinChild;
    }

    public void setCertMutatorSelftest(boolean certMutatorSelftest) {
        this.certMutatorSelftest = certMutatorSelftest;
    }

    public boolean isCertMutatorSelfTest() {
        return certMutatorSelftest;
    }

    private static final Logger LOG = Logger.getLogger(EvolutionaryFuzzerConfig.class.getName());
}
