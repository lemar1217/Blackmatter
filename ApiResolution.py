#@author lemar1217
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.program.model.address import GenericAddress
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import ReferenceManager
from ghidra.program.model.listing import FunctionManager, CodeUnit
import json
import traceback
 
class ResolveApiHashScript(GhidraScript):
    def __init__(self):
        super(ResolveApiHashScript, self).__init__()
        self.hash_dict = {}
        self.export_hashes = {}


       
    def run(self):
        try:
            self.set('C:\\Users\\Elias\\Downloads\\data.json')
            function_name = self.ask_for_function_name()
            xor_key = self.get_xor_key_from_user()
            if function_name and xor_key:
           
              self.Api_Resolving(function_name,xor_key)
        except IOError as e:
          if e.errno == errno.EACCES:  # Permission Denied
            print("Permission denied for the Json file")
          elif e.errno == errno.ENOENT:  # File Not Found
             print("The file could not be found")
        except ValueError:
             print("Invalid value received")
        except Exception as e:
             print("An unexpected error occurred {}".format(e))                 
    
    # Your existing functions go here (with slight modifications)
    # e.g.:
    def ror(self, n, rotations, width):
        mask = (1 << width) - 1
        return (n >> rotations | n << (width - rotations)) & mask
    
    hash_dict = {}
    def hash_dll(self, dll_name, start):
        if dll_name in self.hash_dict:
            return self.hash_dict[dll_name] 
    
        result = start
        dll_bytes = [ord(c)for c in dll_name]

        for b in dll_bytes:
           temp = b
           if 0x41 <= temp <= 0x5a:
              temp |= 0x20
           result = temp + self.ror(result,13,32)

     
        self.hash_dict[dll_name] = result
        return result
    def hash_API(self, API_name,start):
      result = start
      mask = (1 << 32) -1

      for each in API_name:

        rotated_result = (result >> 13 | result << (32 - 13)) & mask 

        result = ord(each) + rotated_result

      rotated_result = (result >> 13 | result << (32 - 13)) & mask 
    
      return rotated_result 
    def hashing(self,name):
        dll_name,ApiName = name.split(':')
        dll_hash = self.hash_dll(dll_name,0)
        Api_hash = self.hash_API(ApiName,dll_hash)

        return Api_hash
    export_hashes = {}
    def set(self, json_file):
     try:
        with open(json_file, 'r') as f:
            print("Successfully opened {}".format(json_file))
            export_json = json.load(f)
        for export in export_json.get('exports', []):
            api_hash = self.hashing(export)
            export_name = export.split(':')[1]
            self.export_hashes[api_hash] = export_name  # Using self.export_hashes
     except IOError as e:
       if e.errno == errno.EACCES:  # Permission Denied
        print("Permission denied for the Json file")
       elif e.errno == errno.ENOENT:  # File Not Found
        print("The file could not be found")
     except ValueError:
        print("Invalid value received")
     except Exception as e:
        print("An unexpected error occurred {}".format(e))
    
    
    def resolve_api_hash(self, API_hashes_ea, xor_key):
     print("Debug: API_hashes_ea={}".format(API_hashes_ea))
     index = 0

     while True:
          addr = toAddr(API_hashes_ea + 4 * index)
          if not currentProgram.getMemory().contains(addr):
            print("Addres {} is not valid in memory space".format(addr))
            return
          Api_hash_bytes = getBytes(addr, 4)
        
          if not Api_hash_bytes:
            break

          API_hash = int.from_bytes(Api_hash_bytes, "little")

          if API_hash == 0xCCCCCCCC:
              break

          API_hash ^= xor_key  # XOR operation

          self.resolve_and_label(API_hash, API_hashes_ea, index)
          index += 1

         
    
    def resolve_and_label(self, API_hash, API_hashes_ea, index):
         if API_hash in self.export_hashes:
          print(self.export_hashes[API_hash])
          label_addr = toAddr(API_hashes_ea + 4 * index)
          createLabel(label_addr, 'mw_{}'.format(self.export_hashes[API_hash]), True)

    def get_xor_key_from_user(self):
        user_input = self.askString("Resolve API","Enter the XOR key:")
        try:
            return int(user_input, 16)
        except ValueError:
            self.println("Invalid input. Please enter a valid hexadecimal number.")
            return None

    def ask_for_function_name(self):
        function_name = self.askString("Resolve API","Enter the function name")
        if function_name is None or function_name.strip() == '':
            self.println("No function name provided. Exiting.")
            return None
        return function_name

    def Api_Resolving(self, function_name,xor_key):
        try: 
            print("Api_Resolving function started")

            function_manager = currentProgram.getFunctionManager()
            target_address = None
            for function in function_manager.getFunctions(True):
                print(function.getName())
                if function.getName() == function_name:
                 target_address = function.getEntryPoint()
            if target_address is None: 
                print("function {} not found".format(function_name))
                return
            memory = currentProgram.getMemory()
            if memory .contains(target_address):
                 print("Address is in valiid memory space")

            else:
                 print("Address is not in valid memory space")

            print("Debug: Got the Fucntion Manager")
            print("Debug:target_address type",type(target_address))

          
            
            function = function_manager.getFunctionAt(target_address) 
            if function is not None: 
               print("Function found : {} found at {}".format( function.getName(), function.getEntryPoint()))
            else:
                print("Function not found at address {}".format(target_address))

             
            API_addresses_ea = 0
            API_hashes_ea = 0
        
            resolve_entry_point = function.getEntryPoint()
            curr_instruction = getInstructionAt(resolve_entry_point)

            while True:
                curr_instruction = curr_instruction.getPrevious()
                if curr_instruction is None:
                    break
                
                print("Debug: Current instruction = {}".format(curr_instruction))
                if curr_instruction.getMnemonicString() == 'PUSH':
                    scalar_value = curr_instruction.getScalar(0)
                    if scalar_value is not None:
                        print("scalar value = {}".format(scalar_value.getValue()))
                        if API_addresses_ea == 0:
                             API_addresses_ea = scalar_value.getValue()
                    
                        else:
                             API_hashes_ea = operand_value
                    
                    else:
                        print("Warning: Scalar value is None for instruction at {}".format(curr_instruction.getAddress()))

            if xor_key is None: 
                print("Please insert a key")
                return
            
            self.resolve_api_hash(API_hashes_ea,xor_key)


      
        except IOError as e:
          if e.errno == errno.EACCES:  # Permission Denied
            print("Permission denied for the Json file")
          elif e.errno == errno.ENOENT:  # File Not Found
            print("The file could not be found")
        except ValueError as ve:
            print("Invalid value received")
            print(str(ve))
            traceback.print_exc()
        except Exception as e:
            print("An unexpected error occurred {}".format(e))           
        
if __name__ == '__main__':
    ResolveApiHashScript().run()
