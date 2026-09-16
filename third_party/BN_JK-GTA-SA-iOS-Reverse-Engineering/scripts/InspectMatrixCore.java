//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class InspectMatrixCore extends BN_JKScript {

    long[] targets = {
        0x10022a780L,
        0x10022a7c8L,
        0x10022a6bcL,
        0x10016c360L,
        0x10016c3f8L,
        0x10016c634L,
        0x10016c648L,
        0x10016ca24L
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/matrix_core.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        for (long t : targets) {

            Address a = toAddr(t);
            Function f = fm.getFunctionAt(a);

            out.println();
            out.println("================================================");
            out.println("TARGET=" + Long.toHexString(t));

            if (f == null) {
                f = fm.getFunctionContaining(a);
            }

            if (f == null) {
                out.println("NO_FUNCTION");
                continue;
            }

            out.println(
                "FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );

            out.println("BODY=" + f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults dr =
                dec.decompileFunction(f, 120, monitor);

            if (dr.decompileCompleted()) {
                out.println(
                    dr.getDecompiledFunction().getC()
                );
            } else {
                out.println(
                    "FAILED=" +
                    dr.getErrorMessage()
                );
            }

            out.println();
            out.println("=== INSTRUCTIONS ===");

            InstructionIterator ii =
                listing.getInstructions(
                    f.getBody(),
                    true
                );

            while (ii.hasNext()) {
                Instruction ins = ii.next();

                out.println(
                    ins.getAddress() +
                    " | " +
                    ins
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

        println("MATRIX_CORE_COMPLETE");
    }
}
