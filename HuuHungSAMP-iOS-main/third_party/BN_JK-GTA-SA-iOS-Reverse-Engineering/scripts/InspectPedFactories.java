//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class InspectPedFactories extends BN_JKScript {

    long allocator = 0x10023cb7cL;
    long pedCtor   = 0x10023c0a4L;
    long worldAdd  = 0x1001826acL;
    long modelSet  = 0x100141e00L;

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_factories.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        Function allocFn =
            fm.getFunctionAt(toAddr(allocator));

        if (allocFn == null) {
            out.println("ALLOCATOR_NOT_FOUND");
            out.close();
            return;
        }

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        Set<Function> candidates =
            allocFn.getCallingFunctions(monitor);

        out.println("ALLOCATOR=" + allocFn.getEntryPoint());
        out.println("CALLER_COUNT=" + candidates.size());

        for (Function f : candidates) {

            out.println();
            out.println("================================================");
            out.println(
                "FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );

            boolean callsCtor = false;
            boolean callsWorld = false;
            boolean callsModel = false;

            for (Function callee :
                    f.getCalledFunctions(monitor)) {

                long e =
                    callee.getEntryPoint().getOffset();

                if (e == pedCtor)
                    callsCtor = true;

                if (e == worldAdd)
                    callsWorld = true;

                if (e == modelSet)
                    callsModel = true;
            }

            out.println("CALLS_PED_CTOR=" + callsCtor);
            out.println("CALLS_WORLD_ADD=" + callsWorld);
            out.println("CALLS_MODEL_SET=" + callsModel);

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults dr =
                dec.decompileFunction(f, 120, monitor);

            if (dr.decompileCompleted()) {
                out.println(
                    dr.getDecompiledFunction().getC()
                );
            }
            else {
                out.println(
                    "FAILED=" + dr.getErrorMessage()
                );
            }

            out.println();
            out.println("=== CALL INSTRUCTIONS ===");

            InstructionIterator ii =
                listing.getInstructions(f.getBody(), true);

            while (ii.hasNext()) {

                Instruction ins = ii.next();

                String s = ins.toString();

                if (s.startsWith("bl ") ||
                    s.startsWith("blr ")) {

                    out.println(
                        ins.getAddress() +
                        " | " +
                        s
                    );
                }
            }

            out.println();
            out.println("=== CALLEES ===");

            for (Function c :
                    f.getCalledFunctions(monitor)) {

                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
            }
        }

        out.close();

        println("PED_FACTORIES_COMPLETE");
    }
}
