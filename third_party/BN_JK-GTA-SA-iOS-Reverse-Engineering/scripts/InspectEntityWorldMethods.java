//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectEntityWorldMethods extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n, long a) {
            name = n;
            addr = a;
        }
    }

    T[] targets = {
        new T("Virtual10_SectorInsert", 0x100160634L),
        new T("Virtual18",              0x1001449b4L),
        new T("Virtual20",              0x100160834L),
        new T("Wrapper144968",          0x100144968L),
        new T("OtherWrapper16091C",     0x10016091cL),
        new T("Virtual50",              0x1001605e8L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/entity_world_methods.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        for (T t : targets) {

            Address a = toAddr(t.addr);
            Function f = fm.getFunctionAt(a);

            if (f == null)
                f = fm.getFunctionContaining(a);

            out.println();
            out.println("================================================");
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

            DecompileResults dr =
                dec.decompileFunction(f, 180, monitor);

            if (dr.decompileCompleted()) {
                out.println(dr.getDecompiledFunction().getC());
            } else {
                out.println("FAILED=" + dr.getErrorMessage());
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
            }

            out.println();
            out.println("=== CALLERS ===");

            for (Function c :
                    f.getCallingFunctions(monitor)) {

                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
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

        println("ENTITY_WORLD_METHODS_COMPLETE");
    }
}
