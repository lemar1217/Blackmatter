//@author lemar  (building up on a script of jgru)
//@category _NEW_
//@keybinding
//@menupath
//@toolbar


import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;  // <-- Added
import java.util.Collections; 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;

public class BlackMatterHashing extends GhidraScript {

	@Override
	public void run() throws Exception {
		String resolverFunc =  getResolverFunc();
		if(resolverFunc == null) return;

		long xorValue = getXorValue();
		if(xorValue == -1)return; 

		File apiHashFile = getApiHashFile();
		if(apiHashFile == null) return;
		
		HashMap<Long, String> hashToFunc = parseHashFile(apiHashFile);
		
		for (Address callAddr : getCallAddresses(resolverFunc)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			resolveSingleCall(callAddr, hashToFunc, xorValue);
		}
	}


	private String getResolverFunc() {
    try {
        return askString("Enter Name", "Enter the name of the API resolution function:", getFunctionBefore(currentAddress.next()).getName());
    } catch (Exception e) {
        println("An error occurred: " + e.getMessage());
        return null;
    }
  }

  private long getXorValue() {
    try {
        return askInt("Enter the XOR key", "Enter the XOR key");
    } catch (Exception e) {
        println("An error occurred: " + e.getMessage());
        return -1; // Some invalid value
    }
  }

private File getApiHashFile() {
    try {
        return askFile("Hash List", "Open");
    } catch (Exception e) {
        println("An error occurred: " + e.getMessage());
        return null;
    }
  }

	

	private void resolveSingleCall(Address callAddr, HashMap<Long, String> map, long xorValue) throws Exception {
		int arguments[] = { 1, 2 };
		OptionalLong options[] = getConstantCallArgument(callAddr, arguments);

		if (options[0].isEmpty() || options[1].isEmpty()) {
			println(String.format("Argument to call at %08X is not a block of memory.", callAddr.getOffset()));
			return;
		}
		long result = options[0].getAsLong();
		long hash = options[1].getAsLong();

		if (result == 0 || hash == 0) {
			return;
		}
		println(String.format("Array of API hashes at %08X\nArray of function pointers at %08X", hash, result));

		Address resultAddr = currentAddress.getNewAddress(result);
		Address hashAddr = currentAddress.getNewAddress(hash);

		// Perform the resolution and label the addresses
		resolveApiHash(map, hashAddr, resultAddr, xorValue);
	}
	
	private void resolveApiHash(HashMap<Long, String> hm, Address hashAddr, Address resultAddr, long xorValue) {
		// Skip module hash
		Address currentHashAddr = hashAddr.add(4);
		Address currentResultAddr = resultAddr.add(4);

		while(currentHashAddr != null && !monitor.isCancelled()){
			long hashValue = ReadIntFromMemory(currentHashAddr);
			if (IsEndingOfList(hashValue)) return;
			long ActualHash = applyXorMask(hashValue,xorValue);
			resolveAndLabelFunction(hm,currentResultAddr,ActualHash); 
			
			currentHashAddr = currentHashAddr.add(4);
			currentResultAddr = currentResultAddr.add(4);

		}


		
	}

	private long ReadIntFromMemory(Address addr){
		try{
			return getInt(addr) & 0xFFFFFFFFL; 

		}catch(MemoryAccessException e){
	       e.printStackTrace();
		   throw new RuntimeException("Memory access failed",e); 	
		}  
	}

	private boolean IsEndingOfList(long value){
		
		return value == 0xCCCCCCCCL;

	}

	private long applyXorMask(long value,long xorValue){
		return(value ^ xorValue) & 0xFFFFFFFFL;

	}
	private void resolveAndLabelFunction(HashMap<Long,String> hm, Address resultAddr, long ActualHash){
	   try {
        String functionName = hm.get(ActualHash);
        if (functionName != null) {
            println(String.format("%08X %s", resultAddr.getOffset(), functionName));
            createLabel(resultAddr, functionName, true);
            createDWord(resultAddr);
        } else {
            println(String.format("Unknown hash at address: %08X", resultAddr.getOffset()));
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
  }









	private List<Address> getCallAddresses(String functionName) {
		List<Function> functions = getGlobalFunctions(functionName);
		Function resolver = functions.get(0);
	    List<Address> addresses = new ArrayList<>();
		for(Reference ref: getReferencesTo(resolver.getEntryPoint()) ){
			if(ref.getReferenceType()==RefType.UNCONDITIONAL_CALL){
				addresses.add(ref.getFromAddress());
			}
		}
		return  addresses;
	}

	private static final Pattern PATTERN = Pattern.compile("\\{\"dll\":\\s*\"(.*?)\",\\s*\"name\":\\s*\"(.*?)\",\\s*\"hash\":\\s*(\\d+)\\}"); 

	private HashMap<Long, String> parseHashFile(File apiHashFile){
		//initiliaze the new hash

		HashMap<Long, String> hm= new HashMap<>();
		try(Stream<String> lines = Files.lines(apiHashFile.toPath(),Charset.defaultCharset())){
			lines.forEach(line->{
                Matcher matcher = PATTERN.matcher(line);
				if(matcher.find()){
				   long hash = Long.parseLong(matcher.group(3));
				   String name = matcher.group(2);
				   hm.put(hash, name);

				}
			});

		}catch(IOException e){
			this.println(String.format("File not found",apiHashFile.getAbsolutePath()));
			return null;
		}

		return hm; 



	}

	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}

	private OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null)
				break;
			switch (ins.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				argument = ins.getInput(0);
				break;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				argument = ins.getInput(1);
				break;
			case PcodeOp.INT_MULT:
			case PcodeOp.MULTIEQUAL:
				// known cases where an array is indexed
				return OptionalLong.empty();
			default:
				// don't know how to handle this yet.
				throw new UnknownVariableCopy(ins, argument.getAddress());
			}
		}
		return OptionalLong.of(argument.getOffset());
	}

	private OptionalLong[] getConstantCallArgument(Address addr, int[] argumentIndices)
			throws IllegalStateException, UnknownVariableCopy {
		validateInputs(addr,argumentIndices);
		OptionalLong argumentValues[] = new OptionalLong[argumentIndices.length];
		Function caller = getFunctionBefore(addr);
		if (caller == null)
			throw new IllegalStateException();

		DecompInterface decompInterface = setupDecompiler();
		DecompileResults decompileResults = decompInterface.decompileFunction(caller,120,monitor );
		if (!decompileResults.decompileCompleted()){
			throw new IllegalArgumentException(
				"Decompile failed"
			);

		}
		HighFunction highFunction = decompileResults.getHighFunction();
		Iterator<PcodeOpAST> pcodeInstructions = highFunction.getPcodeOps(addr);
		extractArguments(argumentIndices,argumentValues,pcodeInstructions);
		return argumentValues; 
	}

	private DecompInterface setupDecompiler(){
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		return decompInterface;

	}

	private void extractArguments(int[] argumentIndices,OptionalLong[]argumentsValues,Iterator<PcodeOpAST>pcodeInstructions)throws UnknownVariableCopy{
       int argumentPos = 0;
	   while(pcodeInstructions.hasNext()){
		 PcodeOpAST instruction = pcodeInstructions.next();
		 if(instruction.getOpcode()==PcodeOp.CALL){
			for( int index : argumentIndices){
				argumentsValues[argumentPos] = traceVarnodeValue(instruction.getInput(index)); 
				argumentPos++; 
			}

		 }
		 break;
	   }
	}
	private void validateInputs(Address addr, int[] argumentIndices){
		if( addr == null){
			throw new IllegalArgumentException("Address cannot be null");

		}
		if(argumentIndices == null ){
			throw new IllegalArgumentException("Arguments can not be null"); 

		}
	}
}
