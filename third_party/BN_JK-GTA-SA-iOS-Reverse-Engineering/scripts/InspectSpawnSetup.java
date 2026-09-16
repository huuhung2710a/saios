//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectSpawnSetup extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n,long a) {
            name=n;
            addr=a;
        }
    }

    T[] targets = {
        new T("PlayerCtorStage",  0x10026cd04L),
        new T("PlayerSetup",      0x100246c38L),
        new T("MatrixOperation",  0x10022a904L),
        new T("GetBoundRectBase", 0x1001430f8L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/spawn_setup.txt"
        );

        FunctionManager fm =
            currentProgram.getFunctionManager();

        Listing listing =
            currentProgram.getListing();

        DecompInterface dec =
            new DecompInterface();

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

            DecompileResults r =
                dec.decompileFunction(
                    f,
                    180,
                    monitor
                );

            if (r.decompileCompleted())
                out.println(
                    r.getDecompiledFunction().getC()
                );
            else
                out.println(
                    "FAILED=" +
                    r.getErrorMessage()
                );

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

        println("SPAWN_SETUP_COMPLETE");
    }
}
