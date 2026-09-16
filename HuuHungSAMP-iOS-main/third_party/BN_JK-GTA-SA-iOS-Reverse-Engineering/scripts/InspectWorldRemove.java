//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectWorldRemove extends BN_JKScript {

    static class T {
        String name;
        long addr;
        T(String n,long a){name=n;addr=a;}
    }

    T[] targets = {
        new T("SectorRemoveCandidate", 0x100144968L),
        new T("SectorAdd",             0x100160634L),
        new T("WorldPostCreate",       0x1001826acL)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/world_add_remove.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        for(T t:targets){

            Address a=toAddr(t.addr);
            Function f=fm.getFunctionAt(a);

            if(f==null)
                f=fm.getFunctionContaining(a);

            out.println();
            out.println("========================================");
            out.println("NAME="+t.name);
            out.println("TARGET="+a);

            if(f==null){
                out.println("NOT_FOUND");
                continue;
            }

            out.println("FUNCTION="+f.getName());
            out.println("ENTRY="+f.getEntryPoint());
            out.println("BODY="+f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults r =
                dec.decompileFunction(f,180,monitor);

            if(r.decompileCompleted())
                out.println(r.getDecompiledFunction().getC());
            else
                out.println("FAILED="+r.getErrorMessage());

            out.println();
            out.println("=== CALLERS ===");

            for(Function c:f.getCallingFunctions(monitor))
                out.println(c.getEntryPoint()+"|"+c.getName());

            out.println();
            out.println("=== CALLEES ===");

            for(Function c:f.getCalledFunctions(monitor))
                out.println(c.getEntryPoint()+"|"+c.getName());
        }

        out.close();

        println("WORLD_ADD_REMOVE_COMPLETE");
    }
}
