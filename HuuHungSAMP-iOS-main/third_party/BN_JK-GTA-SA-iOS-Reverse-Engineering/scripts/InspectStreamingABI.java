//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectStreamingABI extends BN_JKScript {

    long[] targets = {
        0x100307d54L,
        0x1003078a4L
    };

    String[] names = {
        "RequestModel",
        "LoadRequestedModels"
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/streaming_abi.txt"
        );

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        Listing listing = currentProgram.getListing();

        for (int n = 0; n < targets.length; n++) {

            Function f = getFunctionAt(toAddr(targets[n]));

            if (f == null)
                f = getFunctionContaining(toAddr(targets[n]));

            out.println();
            out.println("================================================");
            out.println("NAME=" + names[n]);
            out.printf("TARGET=0x%X%n", targets[n]);

            if (f == null) {
                out.println("NOT_FOUND");
                continue;
            }

            out.println(
                "FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );

            out.println("=== DECOMPILE ===");

            DecompileResults dr =
                dec.decompileFunction(f, 180, monitor);

            if (dr.decompileCompleted())
                out.println(dr.getDecompiledFunction().getC());
            else
                out.println("DECOMPILE_FAILED=" + dr.getErrorMessage());

            out.println("=== INSTRUCTIONS ===");

            InstructionIterator ii =
                listing.getInstructions(f.getBody(), true);

            while (ii.hasNext()) {

                Instruction ins = ii.next();

                out.println(
                    ins.getAddress() +
                    " | " +
                    ins
                );
            }

            out.println("=== CALLERS ===");

            for (Function c : f.getCallingFunctions(monitor)) {
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
            }

            out.println("=== CALLEES ===");

            for (Function c : f.getCalledFunctions(monitor)) {
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
            }
        }

        dec.dispose();
        out.close();

        println("STREAMING_ABI_COMPLETE");
    }
}
