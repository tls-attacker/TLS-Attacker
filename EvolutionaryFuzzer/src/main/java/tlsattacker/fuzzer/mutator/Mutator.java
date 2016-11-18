/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Random;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.helper.GitIgnoreFileFilter;
import tlsattacker.fuzzer.testvector.TestVector;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;

/**
 * The Mutator is the generator of new FuzzingVectors, different Implementations
 * should implement different Strategies to generate new Workflowtraces to be
 * executed.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Mutator {

    /**
     * The config used
     */
    protected EvolutionaryFuzzerConfig config;

    /**
     * The ceritficate Mutator that this mutator uses
     */
    protected CertificateMutator certMutator;

    public Mutator(EvolutionaryFuzzerConfig config, CertificateMutator certMutator) {
        this.config = config;
        this.certMutator = certMutator;
    }

    public CertificateMutator getCertMutator() {
        return certMutator;
    }

    /**
     * Checks if good TestVectors already exist
     *
     * @return True if good TestVectors exist
     */
    protected boolean goodVectorsExist() {
        File f = new File("data/good/"); // TODO fixed FILE
        return f.listFiles().length > 0;

    }

    /**
     * Checks if TestVectors exist in the archive Folder
     *
     * @return True if archive TestVectors exist
     */
    protected boolean archiveVectorsExist() {
        File f = new File("archive/"); // TODO Fixed FILE
        return f.listFiles().length > 0;
    }

    /**
     * Chooses a random TestVector from a folder
     *
     * @param folder
     *            Folder to choose from
     * @return A random TestVector in the folder
     * @throws IOException
     *             If something goes wrong while reading
     * @throws JAXBException
     *             If desirialisation goes wrong
     * @throws XMLStreamException
     *             If desirialisation goes wrong
     */
    protected TestVector chooseRandomTestVectorFromFolder(File folder) throws IOException, JAXBException,
            XMLStreamException {
        TestVector chosenTestVector = null;
        int tries = 0;
        if (folder.exists() && folder.isDirectory()) {
            do {
                File[] files = folder.listFiles(new GitIgnoreFileFilter());
                Random r = new Random();
                File chosenFile = files[r.nextInt(files.length)];
                try {
                    chosenTestVector = TestVectorSerializer.read(new FileInputStream(chosenFile));
                } catch (IOException | JAXBException | XMLStreamException E) {
                    throw new IOException("Could not read TestVector from file:" + chosenFile.getAbsolutePath());
                }
            } while (chosenTestVector == null && tries < 1000);
            if (chosenTestVector == null) {
                throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
            }
        } else {
            throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
        }
        return chosenTestVector;

    }

    /**
     * Generates a new TestVector to execute
     *
     * @return New TestVector
     */
    public abstract TestVector getNewMutation();
}
