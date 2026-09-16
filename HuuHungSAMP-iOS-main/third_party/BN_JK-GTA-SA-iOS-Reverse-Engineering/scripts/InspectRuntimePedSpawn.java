//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectRuntimePedSpawn extends BN_JKScript {

    long[] targets = {
        0x10027aa30L, // multi ped spawn
        0x100116e68L, // minimal CCopPed spawn
        0x10023cb7cL, // runtime pool allocation
        0x10023cc08L, // pool allocation/load variant
        0x10023b2b8L, // CCivilianPed ctor
        0x1001826acL  // post-create/world
    };

    String[] names = {
        "MultiPedSpawn",
        "MinimalCopSpawn",
        "PedPoolNew",
        "PedPoolNewAt",
        "CivilianCtor",
        "PostCreateWorld"
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/runtime_ped_spawn.txt"
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
                out.println("DECOMPILE_FAILED");

            out.println("=== INSTRUCTIONS ===");

            InstructionIterator ii =
                listing.getInstructions(f.getBody(), true);

            while (ii.hasNext()) {
                Instruction i = ii.next();
                out.println(
                    i.getAddress() +
                    " | " +
                    i
                );
            }

            out.println("=== CALLERS ===");

            for (Function c : f.getCallingFunctions(monitor))
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );

            out.println("=== CALLEES ===");

            for (Function c : f.getCalledFunctions(monitor))
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
        }

        dec.dispose();
        out.close();

        println("RUNTIME_PED_SPAWN_COMPLETE");
    }
}
