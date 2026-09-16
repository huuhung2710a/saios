//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectPedVehicleCore extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n, long a) {
            name = n;
            addr = a;
        }
    }

    T[] targets = {
        new T("CPed_writer_A",       0x10023c0a4L),
        new T("CPed_writer_B",       0x10023c83cL),

        new T("CPlayerPed_writer_A", 0x10026cb64L),
        new T("CPlayerPed_writer_B", 0x10026cec8L),

        new T("CVehicle_writer_A",   0x10040815cL),
        new T("CVehicle_writer_B",   0x100408558L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_vehicle_core.txt"
        );

        FunctionManager fm =
            currentProgram.getFunctionManager();

        DecompInterface decomp =
            new DecompInterface();

        decomp.openProgram(currentProgram);

        for (T t : targets) {

            Address a = toAddr(t.addr);

            Function f = fm.getFunctionAt(a);

            if (f == null)
                f = fm.getFunctionContaining(a);

            out.println();
            out.println(
                "================================================"
            );
            out.println("NAME=" + t.name);
            out.println("TARGET=" + a);

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
                decomp.decompileFunction(
                    f,
                    180,
                    monitor
                );

            if (r.decompileCompleted()) {
                out.println(
                    r.getDecompiledFunction().getC()
                );
            } else {
                out.println(
                    "DECOMPILE_FAILED=" +
                    r.getErrorMessage()
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

        println("PED_VEHICLE_CORE_COMPLETE");
    }
}
