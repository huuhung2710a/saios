//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class InspectPlaceableFamily extends BN_JKScript {

    long START = 0x10016c300L;
    long END   = 0x10016ca50L;

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/placeable_family.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        FunctionIterator fi =
            fm.getFunctions(toAddr(START), true);

        while (fi.hasNext()) {

            Function f = fi.next();

            long ea =
                f.getEntryPoint().getOffset();

            if (ea > END)
                break;

            out.println();
            out.println("================================================");
            out.println(
                "FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );
            out.println("BODY=" + f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults dr =
                dec.decompileFunction(f, 120, monitor);

            if (dr.decompileCompleted())
                out.println(
                    dr.getDecompiledFunction().getC()
                );
            else
                out.println(
                    "FAILED=" +
                    dr.getErrorMessage()
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
                String s = ins.toString();

                if (
                    s.contains("#0x8]")  ||
                    s.contains("#0xc]")  ||
                    s.contains("#0x10]") ||
                    s.contains("#0x14]") ||
                    s.contains("#0x18]") ||
                    s.contains("#0x30]") ||
                    s.contains("#0x34]") ||
                    s.contains("#0x38]") ||
                    s.contains("10043de14")
                ) {
                    out.println(
                        ins.getAddress() +
                        " | " +
                        ins
                    );
                }
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

        println("PLACEABLE_FAMILY_COMPLETE");
    }
}
