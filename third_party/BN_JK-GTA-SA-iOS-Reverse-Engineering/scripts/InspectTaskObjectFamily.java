//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;

public class InspectTaskObjectFamily extends BN_JKScript {

    private long[] targets = {
        0x100361f7cL,
        0x100361398L,
        0x100361c94L,
        0x1003610a8L,
        0x100360eb4L
    };

    @Override
    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/task_object_family.txt"
        );

        Listing listing = currentProgram.getListing();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (long value : targets) {

            Address addr = toAddr(value);

            Function f = listing.getFunctionAt(addr);

            if (f == null)
                f = listing.getFunctionContaining(addr);

            out.println();
            out.println("================================================");
            out.println("TARGET=" + addr);

            if (f == null) {
                out.println("FUNCTION_NOT_FOUND");
                continue;
            }

            out.println("FUNCTION=" + f.getName());
            out.println("ENTRY=" + f.getEntryPoint());
            out.println("BODY=" + f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults result =
                decomp.decompileFunction(f, 120, monitor);

            if (result.decompileCompleted()) {
                out.println(
                    result.getDecompiledFunction().getC()
                );
            } else {
                out.println(
                    "DECOMPILE_FAILED=" +
                    result.getErrorMessage()
                );
            }

            out.println();
            out.println("=== CALLERS ===");

            for (Function caller :
                    f.getCallingFunctions(monitor)) {

                out.println(
                    caller.getEntryPoint() +
                    "|" +
                    caller.getName()
                );
            }

            out.println();
            out.println("=== CALLEES ===");

            for (Function callee :
                    f.getCalledFunctions(monitor)) {

                out.println(
                    callee.getEntryPoint() +
                    "|" +
                    callee.getName()
                );
            }
        }

        out.close();

        println("TASK_OBJECT_FAMILY_COMPLETE");
    }
}
