//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectPedPoolFree extends BN_JKScript {

    public void run() throws Exception {

        long addr = 0x10023cb2cL;

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_pool_free.txt"
        );

        Function f = getFunctionAt(toAddr(addr));

        if (f == null)
            f = getFunctionContaining(toAddr(addr));

        if (f == null) {
            out.println("NOT_FOUND");
            out.close();
            return;
        }

        out.println("FUNCTION=" +
            f.getEntryPoint() + "|" + f.getName());

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        DecompileResults dr =
            dec.decompileFunction(f,120,monitor);

        out.println("=== DECOMPILE ===");

        if (dr.decompileCompleted())
            out.println(dr.getDecompiledFunction().getC());

        out.println("=== INSTRUCTIONS ===");

        InstructionIterator ii =
            currentProgram.getListing()
                .getInstructions(f.getBody(),true);

        while(ii.hasNext()) {
            Instruction ins = ii.next();
            out.println(ins.getAddress() + " | " + ins);
        }

        out.println("=== CALLERS ===");

        for(Function c : f.getCallingFunctions(monitor))
            out.println(c.getEntryPoint() + "|" + c.getName());

        out.println("=== CALLEES ===");

        for(Function c : f.getCalledFunctions(monitor))
            out.println(c.getEntryPoint() + "|" + c.getName());

        dec.dispose();
        out.close();

        println("PED_POOL_FREE_COMPLETE");
    }
}
