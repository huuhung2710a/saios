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

public class InspectTaskDispatcher extends BN_JKScript {

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/task_dispatcher.txt"
        );

        Listing listing = currentProgram.getListing();

        Address addr = toAddr(0x1002d2258L);

        Function f = listing.getFunctionAt(addr);

        if (f == null) {
            f = listing.getFunctionContaining(addr);
        }

        if (f == null) {
            out.println("FUNCTION_NOT_FOUND");
            out.close();
            return;
        }

        out.println("FUNCTION=" + f.getName());
        out.println("ENTRY=" + f.getEntryPoint());
        out.println("BODY=" + f.getBody());
        out.println();

        out.println("=== DECOMPILE ===");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

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
        out.println("=== INSTRUCTIONS ===");

        InstructionIterator it =
            listing.getInstructions(f.getBody(), true);

        while (it.hasNext()) {

            Instruction ins = it.next();

            out.println(
                ins.getAddress() +
                " | " +
                ins
            );

            for (Reference r : ins.getReferencesFrom()) {

                out.println(
                    "    REF=" +
                    r.getToAddress() +
                    " TYPE=" +
                    r.getReferenceType()
                );
            }
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

        out.close();

        println("TASK_DISPATCHER_INSPECT_COMPLETE");
    }
}
