//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectVehicleCtor extends BN_JKScript {

    long[] targets = {
        0x1004233f8L, // CVehicle ctor candidate
        0x10040815cL, // base ctor candidate
        0x100423668L  // CVehicle dtor candidate
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/vehicle_ctor_family.txt"
        );

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (long raw : targets) {

            Address addr = toAddr(raw);
            Function f = fm.getFunctionAt(addr);

            if (f == null)
                f = fm.getFunctionContaining(addr);

            out.println();
            out.println("================================================");
            out.println("TARGET=" + addr);

            if (f == null) {
                out.println("NOT_FOUND");
                continue;
            }

            out.println("FUNCTION=" + f.getName());
            out.println("ENTRY=" + f.getEntryPoint());
            out.println("BODY=" + f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults r =
                decomp.decompileFunction(f, 120, monitor);

            if (r.decompileCompleted())
                out.println(r.getDecompiledFunction().getC());
            else
                out.println("DECOMPILE_FAILED=" + r.getErrorMessage());

            out.println();
            out.println("=== CALLERS ===");

            for (Function caller : f.getCallingFunctions(monitor)) {
                out.println(
                    caller.getEntryPoint() + "|" + caller.getName()
                );
            }

            out.println();
            out.println("=== CALLEES ===");

            for (Function callee : f.getCalledFunctions(monitor)) {
                out.println(
                    callee.getEntryPoint() + "|" + callee.getName()
                );
            }
        }

        out.close();
        println("VEHICLE_CTOR_FAMILY_COMPLETE");
    }
}
