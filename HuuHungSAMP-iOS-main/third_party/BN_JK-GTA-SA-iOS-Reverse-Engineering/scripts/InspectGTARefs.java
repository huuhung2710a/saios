//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;

import java.io.*;

public class InspectGTARefs extends BN_JKScript {

    private long[] targets = {
        0x1004a6ae8L, // CPedModelInfo
        0x1004a6ba0L, // CVehicleModelInfo
        0x1004a74d8L, // CPed
        0x1004a95f8L, // CTaskSimple
        0x1004a9610L, // CTaskComplex
        0x1004aa540L, // CTaskSimpleFight
        0x1004aa570L, // CTaskSimpleUseGun
        0x1004aa588L, // CTaskSimpleGunControl
        0x1004aa600L, // CTaskComplexKillPedOnFoot
        0x1004aa678L  // CTaskComplexDestroyCar
    };

    @Override
    public void run() throws Exception {

        File output =
            new File("/root/BN_JK-analysis/output/ref_context.txt");

        PrintWriter out =
            new PrintWriter(new BufferedWriter(new FileWriter(output)));

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        AddressSpace space =
            currentProgram.getAddressFactory().getDefaultAddressSpace();

        out.println("IMAGE_BASE=" + currentProgram.getImageBase());
        out.println();

        for (long value : targets) {

            Address target = space.getAddress(value);

            out.println();
            out.println("==================================================");
            out.println("TARGET=" + target);

            Function containing = fm.getFunctionContaining(target);

            if (containing != null) {
                out.println(
                    "CONTAINING_FUNCTION=" +
                    containing.getEntryPoint() +
                    "|" +
                    containing.getName()
                );
            } else {
                out.println("CONTAINING_FUNCTION=NONE");
            }

            Symbol primary =
                currentProgram.getSymbolTable().getPrimarySymbol(target);

            if (primary != null) {
                out.println(
                    "PRIMARY_SYMBOL=" +
                    primary.getName() +
                    "|" +
                    primary.getSymbolType()
                );
            }

            out.println("--- REFERENCES FROM TARGET ---");

            Reference[] fromRefs = rm.getReferencesFrom(target);

            for (Reference ref : fromRefs) {
                out.println(
                    ref.getFromAddress() +
                    " -> " +
                    ref.getToAddress() +
                    " | " +
                    ref.getReferenceType()
                );
            }

            out.println("--- REFERENCES TO TARGET ---");

            ReferenceIterator toRefs = rm.getReferencesTo(target);

            while (toRefs.hasNext()) {

                Reference ref = toRefs.next();

                out.println(
                    ref.getFromAddress() +
                    " -> " +
                    ref.getToAddress() +
                    " | " +
                    ref.getReferenceType()
                );

                Function f =
                    fm.getFunctionContaining(ref.getFromAddress());

                if (f != null) {
                    out.println(
                        "  FROM_FUNCTION=" +
                        f.getEntryPoint() +
                        "|" +
                        f.getName()
                    );
                }
            }

            out.println("--- LISTING +/- 0x40 ---");

            Address start;

            try {
                start = target.subtract(0x40);
            } catch (Exception e) {
                start = target;
            }

            Address end;

            try {
                end = target.add(0x40);
            } catch (Exception e) {
                end = target;
            }

            CodeUnitIterator units =
                listing.getCodeUnits(start, true);

            while (units.hasNext()) {

                CodeUnit cu = units.next();

                if (cu.getAddress().compareTo(end) > 0)
                    break;

                out.println(
                    cu.getAddress() +
                    " | " +
                    cu.toString()
                );
            }
        }

        out.close();

        println("ZONAAPPLE_REF_CONTEXT_COMPLETE");
    }
}
