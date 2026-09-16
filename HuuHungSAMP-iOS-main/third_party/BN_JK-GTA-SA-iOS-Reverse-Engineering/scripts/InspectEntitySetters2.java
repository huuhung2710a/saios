//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectEntitySetters2 extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n,long a) {
            name=n;
            addr=a;
        }
    }

    T[] targets = {
        new T("ModelIndexPost",      0x100141ee4L),
        new T("PositionCandidateA",  0x1001434c8L),
        new T("PositionCandidateB",  0x100144358L),
        new T("RwObjectCreate",      0x100142940L),
        new T("MatrixFinalize",      0x1002b8070L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/entity_setters2.txt"
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
            out.println("========================================");
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
                dec.decompileFunction(f,180,monitor);

            if (dr.decompileCompleted())
                out.println(dr.getDecompiledFunction().getC());
            else
                out.println("FAILED=" + dr.getErrorMessage());

            out.println();
            out.println("=== INSTRUCTIONS ===");

            InstructionIterator ii =
                listing.getInstructions(f.getBody(),true);

            while(ii.hasNext()) {
                Instruction ins = ii.next();
                out.println(
                    ins.getAddress() +
                    " | " +
                    ins
                );
            }

            out.println();
            out.println("=== CALLERS ===");

            for(Function c : f.getCallingFunctions(monitor))
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );

            out.println();
            out.println("=== CALLEES ===");

            for(Function c : f.getCalledFunctions(monitor))
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
        }

        out.close();

        println("ENTITY_SETTERS2_COMPLETE");
    }
}
