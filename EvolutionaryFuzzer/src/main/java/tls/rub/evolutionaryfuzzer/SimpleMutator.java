/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import static Helper.FuzzingHelper.executeModifiableVariableModification;
import static Helper.FuzzingHelper.getAllModifiableVariableFieldsRecursively;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;

import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
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
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SimpleMutator extends Mutator {

    //private final Node<WorkflowTrace> tree;
    private final ArrayList<WorkflowTrace> list;
    private final TlsContext context;
    private int goodIndex = 0;

    /**
     *
     * @param context
     */
    public SimpleMutator(TlsContext context) {
        //tree = new Node<>(new WorkflowTrace());
        list = new ArrayList<>();
        //read all good traces
        File f = new File("good/");//TODO
        System.out.println("Reading good Traces in:");
        for (File file : f.listFiles()) {
            if (file.getName().startsWith(".")) {
                continue;
            }
            try {
                WorkflowTrace trace = WorkflowTraceSerializer.read(new FileInputStream(file));
                list.add(trace);
            } catch (JAXBException ex) {
                System.out.println(file.getAbsolutePath());
                Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
            } catch (IOException ex) {
                System.out.println(file.getAbsolutePath());
                Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
            } catch (XMLStreamException ex) {
                System.out.println(file.getAbsolutePath());
                Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, "Could not Read:" + file.getName(), ex);
            }
        }
        this.context = context;
        LOG.log(Level.INFO, "Loaded old good Traces:{0}", list.size());
    }

    /**
     *
     * @return
     */
    @Override
    public WorkflowTrace getNewMutation() {
        //Execute all previously found good WorkflowTraces
        if (goodIndex < list.size() && goodIndex != -1) {
            //TODO can make an off by one error
            ResultContainer.getInstance().setSaveGood(false);
            WorkflowTrace t = list.get(goodIndex);
            goodIndex++;
            if (goodIndex == list.size()) {
                goodIndex = -1;
                LOG.log(Level.INFO, "Executed all old good Traces!");
            }
            return t;
        }//Start with the actual Mutating
        else {
            //TODO can make an off by one error
            ResultContainer.getInstance().setSaveGood(true);
            Random r = new Random();
            //wähle ein zufälligen trace aus der liste
            WorkflowTrace tempTrace;
            if (ResultContainer.getInstance().getGoodTraces().isEmpty()) {
                tempTrace = new WorkflowTrace();
                ResultContainer.getInstance().getGoodTraces().add(tempTrace);
            } else {
                tempTrace = ResultContainer.getInstance().getGoodTraces().get(r.nextInt(ResultContainer.getInstance().getGoodTraces().size()));
            }

            WorkflowTrace trace = (WorkflowTrace) UnoptimizedDeepCopy.copy(tempTrace);
            if (trace.getProtocolMessages().isEmpty() || r.nextInt(100) < 10) {
                addRandomMessage(trace);
            }

            if (r.nextInt(10000) == 1) {
                removeRandomMessage(trace);
            }

            List<ModifiableVariableField> variableList = getAllModifiableVariableFieldsRecursively(trace, ConnectionEnd.CLIENT);
            //LOG.log(Level.INFO, ""+trace.getProtocolMessages().size());
            if (variableList.size() > 0) {
                ModifiableVariableField field = variableList.get(r.nextInt(trace.getProtocolMessages().size()));
                String currentFieldName = field.getField().getName();
                String currentMessageName = field.getObject().getClass().getSimpleName();
                executeModifiableVariableModification((ModifiableVariableHolder) field.getObject(), field.getField());
            }
            //System.out.println("----------------------");

            return trace;
        }
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
                list.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
                ArrayList<CompressionMethod> compressionList = new ArrayList<>();
                compressionList.add(CompressionMethod.NULL);
                ((ClientHelloDtlsMessage) m).setSupportedCipherSuites(list);
                ((ClientHelloDtlsMessage) m).setSupportedCompressionMethods(compressionList);
                break;
            case 7:
                m = new ClientHelloMessage(ConnectionEnd.CLIENT);
                list = new LinkedList<>();
                list.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
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
            tempTrace.add(new ArbitraryMessage());
        }
    }

    private ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {
        Random r = new Random();
        while (true) {
            int fieldNumber = r.nextInt(fields.size());
            return fields.get(fieldNumber);
        }
    }

    private static final Logger LOG = Logger.getLogger(SimpleMutator.class.getName());

}
