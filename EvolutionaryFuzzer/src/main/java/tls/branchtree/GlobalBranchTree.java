/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.branchtree;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Set;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DefaultDirectedGraph;

public class GlobalBranchTree
{

    /**
     *
     * @param file
     * @return
     */
    public static DirectedGraph<BranchVertex, CountEdge> buildGraph(File file)
    {
        DirectedGraph<BranchVertex, CountEdge> graph = new DefaultDirectedGraph<>(CountEdge.class);
        try
        {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            Blocktype type;
            /**
             * We got a List containing all Instrumentation Instructions with
             * all ProbeIds. The Plan is now to generate a graph which contains
             * all possible Programflows. To generate this, we use this List
             * multiple Times, performance should not be an issue since it is
             * only built once per implementation.
             */

            //Step 1 Generate the Edges of the Graph
            while ((line = br.readLine()) != null)
            {
                String split[] = line.split(" ");
                long probeID = Long.parseLong(split[1]);
                switch (split[0])
                {
                    case "JMP": //JMP 965766 	jmp	.Lsqr_tail
                        type = Blocktype.JMP;
                        break;
                    case "CALL"://CALL 965767 	call	__rsaz_512_reduce
                        type = Blocktype.CALL;
                        break;
                    case "RET": //RET 965475 	ret
                        type = Blocktype.RET;
                        break;
                    case "LABEL": //LABEL 965475 .L306:
                        type = Blocktype.LABEL;
                        break;
                    case "CNDJMP": //CNDJMP 965477 	jne	.L307
                        type = Blocktype.LABEL;
                        break;
                    case "FUNCTIONLABEL": //FUNCTIONLABEL 965469 BN_add_word:
                        type = Blocktype.FUNCTIONLABEL;
                        break;
                    default:
                        throw new RuntimeException("UNKNOWN BRANCH TYPE");
                }
                graph.addVertex(new BranchVertex(probeID, type));
            }
            br = new BufferedReader(new FileReader(file));
            BranchVertex last = null;
            while ((line = br.readLine()) != null)
            {
                line = line.replace("	", " ");
                line = line.replace("  ", " ");
                String split[] = line.split(" ");
                long probeID = Long.parseLong(split[1]);
                BranchVertex vertex = getVertex(probeID, graph);
                BranchVertex target = null;

                switch (split[0])
                {
                    case "JMP": //JMP 965766 	jmp	.Lsqr_tail
                    case "CALL"://CALL 965767 	call	__rsaz_512_reduce
                        //Place an edge between ProbeID and label
                        //And place an Edge from last to vertex

                        target = getVertex(split[3], graph);
                        if (target == null)
                        {
                            //   System.out.println("Skipping Call:"+line);
                            continue;
                        }
                        graph.addEdge(vertex, target);
                        if (last != null)
                        {
                            graph.addEdge(last, vertex);
                        }

                        last = null;
                        break;
                    case "RET": //RET 965475 	ret
                        //Not much we can do, when we reach a return we have to link all probeids back, we do this in another step
                       
                        break;
                    case "LABEL": //LABEL 965475 .L306:
                        if (last != null)
                        {
                            graph.addEdge(last, vertex);
                        }
                        last = vertex;
                        break;
                    case "CNDJMP": //CNDJMP 965477 	jne	.L307
                        target = getVertex(split[3], graph);
                        if (target == null)
                        {
                            //    System.out.println("Skipping CNDJMP:"+ line);
                            continue;
                        }
                        graph.addEdge(vertex, target);
                        if (last != null)
                        {
                            graph.addEdge(last, vertex);
                        }
                        break;
                    case "FUNCTIONLABEL": //FUNCTIONLABEL 965469 BN_add_word:
                        if (last != null)
                        {
                            graph.addEdge(last, vertex);
                        }
                        last = vertex;
                        break;
                    default:
                        throw new RuntimeException("UNKNOWN BRANCH TYPE");
                }

            }
            //Run a last time to set the returns correctly
            br = new BufferedReader(new FileReader(file));
            while ((line = br.readLine()) != null)
            {
                String split[] = line.split(" ");
                long probeID = Long.parseLong(split[1]);
                BranchVertex vertex = getVertex(probeID, graph);
                BranchVertex target = null;

                switch (split[0])
                {
                    case "RET": //RET 965475 	ret
                        Set<CountEdge> s = graph.incomingEdgesOf(last);
                        for (CountEdge c : s)
                        {
                            graph.addEdge(vertex, graph.getEdgeSource(c));
                        }
                        break;
                    case "FUNCTIONLABEL": //FUNCTIONLABEL 965469 BN_add_word:

                        last = vertex;
                        break;
                }

            }
        }
        catch (Exception E)
        {
            E.printStackTrace();
        }
        return graph;
    }

    /**
     *
     * @param label
     * @param graph
     * @return
     */
    public static BranchVertex getVertex(String label, DirectedGraph<BranchVertex, CountEdge> graph)
    {
        Set<BranchVertex> set = graph.vertexSet();
        BranchVertex v = null;
        int count = 0;
        for (BranchVertex vertex : set)
        {
            if (vertex.getLabel().equals(label))
            {
                v = vertex;
                count++;
                if (count > 1)
                {
                    System.out.println("Multiple Label:" + count + " Label:" + label);
                }
            }
        }
        if (v == null)
        {
            System.out.println("Label not Found:" + label);
        }
        return v;
    }

    /**
     *
     * @param probeID
     * @param graph
     * @return
     * @throws Exception
     */
    public static BranchVertex getVertex(long probeID, DirectedGraph<BranchVertex, CountEdge> graph) throws Exception
    {
        Set<BranchVertex> set = graph.vertexSet();
        BranchVertex v = null;
        int count = 0;
        for (BranchVertex vertex : set)
        {
            if (vertex.getProbeID() == probeID)
            {
                v = vertex;
                count++;
                if (count > 1)
                {
                    //TODO Debug
                    System.out.println("Multiple ProbeID:" + count + " ProbeID:" + probeID);
                    throw new Exception("ProbeID appears more than once in Tree");
                }
            }
        }
        if (v == null)
        {
            //TODO Debug
            System.out.println("Label not found:" + probeID);
        }
        return v;
    }

    private GlobalBranchTree()
    {
    }
}
