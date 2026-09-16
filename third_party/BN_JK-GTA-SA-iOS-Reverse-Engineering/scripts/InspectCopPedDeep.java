// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.

import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.util.*;

public class InspectCopPedDeep extends BN_JKScript {

    private PrintWriter out;
    private DecompInterface decomp;

    private Address A(long v) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(v);
    }

    private Function getFunc(long addr) {
        Address a = A(addr);
        Function f = getFunctionAt(a);
        if (f == null) {
            f = getFunctionContaining(a);
        }
        return f;
    }

    private void dumpFunction(long addr, String name) {
        out.println("================================================");
        out.println("NAME=" + name);
        out.printf("TARGET=0x%X%n", addr);

        Function f = getFunc(addr);

        if (f == null) {
            out.println("FUNCTION=NOT_FOUND");
            return;
        }

        out.println("FUNCTION=" + f.getEntryPoint() + "|" + f.getName());
        out.println("ENTRY=" + f.getEntryPoint());
        out.println("BODY=" + f.getBody());

        out.println("=== DECOMPILE ===");

        try {
            DecompileResults r = decomp.decompileFunction(f, 60, monitor);

            if (r != null && r.decompileCompleted() &&
                r.getDecompiledFunction() != null) {
                out.println(r.getDecompiledFunction().getC());
            } else {
                out.println("DECOMPILE_FAILED");
            }
        } catch (Exception e) {
            out.println("DECOMPILE_EXCEPTION=" + e);
        }

        out.println("=== INSTRUCTIONS ===");

        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);

        while (it.hasNext()) {
            Instruction ins = it.next();
            out.println(ins.getAddress() + " | " + ins);
        }

        dumpCallers(f.getEntryPoint());
    }

    private void dumpCallers(Address target) {
        out.println("=== REFERENCES / CALLERS TO " + target + " ===");

        ReferenceIterator refs =
            currentProgram.getReferenceManager().getReferencesTo(target);

        Set<Address> seen = new LinkedHashSet<>();

        while (refs.hasNext()) {
            Reference ref = refs.next();

            out.println(
                "FROM=" + ref.getFromAddress() +
                " TYPE=" + ref.getReferenceType()
            );

            Function caller =
                getFunctionContaining(ref.getFromAddress());

            if (caller != null) {
                out.println(
                    "  FUNCTION=" +
                    caller.getEntryPoint() + "|" +
                    caller.getName()
                );

                seen.add(caller.getEntryPoint());
            }
        }

        out.println("CALLER_COUNT=" + seen.size());

        for (Address ca : seen) {
            Function caller = getFunctionAt(ca);
            if (caller == null) continue;

            out.println("----------------------------------------");
            out.println(
                "CALLER=" +
                caller.getEntryPoint() + "|" +
                caller.getName()
            );

            try {
                DecompileResults r =
                    decomp.decompileFunction(caller, 60, monitor);

                if (r != null && r.decompileCompleted() &&
                    r.getDecompiledFunction() != null) {
                    out.println(r.getDecompiledFunction().getC());
                }
            } catch (Exception e) {
                out.println("CALLER_DECOMPILE_EXCEPTION=" + e);
            }
        }
    }

    @Override
    protected void run() throws Exception {

        File output =
            new File("/root/BN_JK-analysis/output/cop_ped_deep.txt");

        out = new PrintWriter(new BufferedWriter(new FileWriter(output)));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // CCopPed constructor implementation
        dumpFunction(0x10023B388L, "CCopPed_Ctor");

        // constructor thunk used by callers
        dumpFunction(0x10023B564L, "CCopPed_CtorThunk");

        // destructor implementation candidate
        dumpFunction(0x10023B568L, "CCopPed_DtorCandidate");

        // first virtual destructor thunk
        dumpFunction(0x10023B760L, "CCopPed_VirtualDtorThunk");

        // second destructor / deleting destructor candidate
        dumpFunction(0x10023B764L, "CCopPed_DeletingDtorCandidate");

        out.flush();
        out.close();

        decomp.dispose();

        println("COP_PED_DEEP_COMPLETE");
    }
}
