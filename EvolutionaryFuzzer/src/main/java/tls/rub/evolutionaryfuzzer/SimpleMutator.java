package tls.rub.evolutionaryfuzzer;

import Config.EvolutionaryFuzzerConfig;
import Helper.FuzzingHelper;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import static de.rub.nds.tlsattacker.fuzzer.util.FuzzingHelper.executeModifiableVariableModification;
import static de.rub.nds.tlsattacker.fuzzer.util.FuzzingHelper.getAllModifiableVariableFieldsRecursively;

import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SimpleMutator extends Mutator {

    private static final Logger LOG = Logger.getLogger(SimpleMutator.class.getName());

    //private final Node<WorkflowTrace> tree;
    private final TlsContext context;
    private int goodIndex = 0;

    /**
     *
     * @param context
     * @param config
     */
    public SimpleMutator(TlsContext context, EvolutionaryFuzzerConfig config) {
        super(config);

        this.context = context;

    }

    /**
     *
     * @return
     */
    @Override
    public WorkflowTrace getNewMutation() {

        Random r = new Random();
        //chose a random trace from the list
        WorkflowTrace tempTrace;
        if (ResultContainer.getInstance().getGoodTraces().isEmpty()) {
            tempTrace = new WorkflowTrace();
            ResultContainer.getInstance().getGoodTraces().add(tempTrace);
        } else {
            //Choose a random Trace to modify
            tempTrace = ResultContainer.getInstance().getGoodTraces().get(r.nextInt(ResultContainer.getInstance().getGoodTraces().size()));
        }

        WorkflowTrace trace = (WorkflowTrace) UnoptimizedDeepCopy.copy(tempTrace);
        //perhaps add a message
        if (trace.getProtocolMessages().isEmpty() || r.nextInt(100) < config.getAddMessagePercentage()) {
            addRandomMessage(trace);
        }
        //perhaps remove a message
        if (r.nextInt(100) <= config.getRemoveMessagePercentage()) {
            removeRandomMessage(trace);
        }
        if(trace.getProtocolMessages().isEmpty())
        {
            addRandomMessage(trace);
        }
        //perhaps add records
        if (r.nextInt(100) <= config.getAddRecordPercentage()) {
            FuzzingHelper.addRecordsAtRandom(trace, ConnectionEnd.CLIENT);
        }
        
        //Modify a random field:
        if (r.nextInt(100) >= config.getModifyVariablePercentage()) {
            List<ModifiableVariableField> variableList = getAllModifiableVariableFieldsRecursively(trace, ConnectionEnd.CLIENT);
            //LOG.log(Level.INFO, ""+trace.getProtocolMessages().size());
            if (variableList.size() > 0) {
                ModifiableVariableField field = variableList.get(r.nextInt(variableList.size()));
                String currentFieldName = field.getField().getName();
                String currentMessageName = field.getObject().getClass().getSimpleName();
                //LOG.log(Level.INFO, "Fieldname:{0} Message:{1}", new Object[]{currentFieldName, currentMessageName});
                executeModifiableVariableModification((ModifiableVariableHolder) field.getObject(), field.getField());
            }
        }
        return trace;

    }

    //TODO Unit Test
    private void removeRandomMessage(WorkflowTrace tempTrace) {
        Random r = new Random();
        List<ProtocolMessage> messages = tempTrace.getProtocolMessages();
        messages.remove(r.nextInt(messages.size()));
    }

    //TODO Unit Test
    private void addRandomMessage(WorkflowTrace tempTrace) {
        ProtocolMessage m = null;
        Random r = new Random();
        switch (r.nextInt(19)) {
            case 0:
                m = new AlertMessage(ConnectionEnd.CLIENT);
                break;
            case 1:
                m = new ApplicationMessage(ConnectionEnd.CLIENT);
                break;
            case 2:
                m = new CertificateMessage(ConnectionEnd.CLIENT);
                break;
            case 3:
                m = new CertificateRequestMessage(ConnectionEnd.CLIENT);
                break;
            case 4:
                m = new CertificateVerifyMessage(ConnectionEnd.CLIENT);
                break;
            case 5:
                m = new ChangeCipherSpecMessage(ConnectionEnd.CLIENT);
                break;
            case 6:
                m = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
                LinkedList<CipherSuite> list = new LinkedList<>();
                int limit = new Random().nextInt(0xFF);
                for (int i = 0; i < limit; i++) {
                    list.add(CipherSuite.getRandom());
                }
                ArrayList<CompressionMethod> compressionList = new ArrayList<>();
                compressionList.add(CompressionMethod.NULL);
                ((ClientHelloMessage) m).setSupportedCipherSuites(list);
                ((ClientHelloMessage) m).setSupportedCompressionMethods(compressionList);
                break;
            case 7:
                m = new ClientHelloMessage(ConnectionEnd.CLIENT);
                list = new LinkedList<>();
                limit = new Random().nextInt(0xFF);
                for (int i = 0; i < limit; i++) {
                    list.add(CipherSuite.getRandom());
                }
                compressionList = new ArrayList<>();
                compressionList.add(CompressionMethod.NULL);
                ((ClientHelloMessage) m).setSupportedCipherSuites(list);
                ((ClientHelloMessage) m).setSupportedCompressionMethods(compressionList);
                break;
            case 8:
                m = new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT);
                break;
            case 9:
                m = new HelloVerifyRequestMessage(ConnectionEnd.CLIENT);
                break;
            case 10:
                m = new DHEServerKeyExchangeMessage(ConnectionEnd.CLIENT);
                break;
            case 11:
                m = new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT);
                break;
            case 12:
                m = new ECDHEServerKeyExchangeMessage(ConnectionEnd.CLIENT);
                break;
            case 13:
                m = new FinishedMessage(ConnectionEnd.CLIENT);
                break;
            case 14:
                m = new HeartbeatMessage(ConnectionEnd.CLIENT);
                break;
            case 15:
                m = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
                break;
            case 16:
                m = new ServerHelloDoneMessage(ConnectionEnd.CLIENT);

                break;
            case 17:
                m = new HelloRequestMessage(ConnectionEnd.CLIENT);
                break;

        }
        if (m != null) {
            tempTrace.add(m);
            m = new ArbitraryMessage();
            m.setMessageIssuer(ConnectionEnd.SERVER);
            tempTrace.add(m);
        }
    }

    private ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {
        Random r = new Random();
        while (true) {
            int fieldNumber = r.nextInt(fields.size());
            return fields.get(fieldNumber);
        }
    }

}
