//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectPlayerPedFactory extends BN_JKScript {

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/playerped_factory.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();

        Address a = toAddr(0x10026cf8cL);

        Function f = fm.getFunctionAt(a);

        if (f == null)
            f = fm.getFunctionContaining(a);

        if (f == null) {
            out.println("NOT_FOUND");
            out.close();
            return;
        }

        out.println("FUNCTION=" + f.getName());
        out.println("ENTRY=" + f.getEntryPoint());
        out.println("BODY=" + f.getBody());

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        DecompileResults dr =
            decomp.decompileFunction(f, 180, monitor);

        out.println();
        out.println("=== DECOMPILE ===");

        if (dr.decompileCompleted())
            out.println(dr.getDecompiledFunction().getC());

        out.println();
        out.println("=== CALLERS ===");

        for (Function caller : f.getCallingFunctions(monitor)) {
            out.println(
                caller.getEntryPoint() +
                "|" +
                caller.getName()
            );
        }

        out.println();
        out.println("=== CALLEES ===");

        for (Function callee : f.getCalledFunctions(monitor)) {
            out.println(
                callee.getEntryPoint() +
                "|" +
                callee.getName()
            );
        }

        out.close();

        println("PLAYERPED_FACTORY_COMPLETE");
    }
}
