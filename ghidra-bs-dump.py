import json

IL2CPPINSPECTOR_METADATA_PATH = "c:/dev/metadata.json"
OUTPUT_PATH = "c:/dev/bs-find-addr/bs-methods.bin"

metadata = {}
with open(IL2CPPINSPECTOR_METADATA_PATH) as fp:
    metadata = json.load(fp)

output = []

# re-dump il2cppinspector stuff with method lengths
combined_methods = metadata["addressMap"]["methodDefinitions"] + metadata["addressMap"]["constructedGenericMethods"] + metadata["addressMap"]["apis"]
for method_def in combined_methods:
    method_addr = currentProgram.parseAddress(method_def["virtualAddress"])[0]
    func = currentProgram.functionManager.getFunctionAt(method_addr)
    length = func.getBody().getNumAddresses()
    output.append((method_addr.getOffset(), length, method_def["signature"]))

    # super hacky way of getting some api calls and i hate it
    if method_def in metadata["addressMap"]["apis"] and not func.isThunk(): # the slow train called
        calls = func.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY)
        if len(calls) == 1:
            for call in calls:
                length = call.getBody().getNumAddresses()
                output.append((call.getEntryPoint().getOffset(), length, "api " + func.getName()))

    # follow thunks and steal their lunch money
    thunk_func_name = "thunk " + func.getName()
    while func and func.isThunk():
        thunk = func.getThunkedFunction(False)
        length = thunk.getBody().getNumAddresses()
        output.append((thunk.getEntryPoint().getOffset(), length, thunk_func_name))
        func = thunk

output.sort(key=lambda x: x[0])

import struct
with open(OUTPUT_PATH, "wb") as fp:
    for entry in output:
        fp.write(struct.pack("<L", entry[0]))
        fp.write(struct.pack("<L", entry[1]))
        # fp.write(struct.pack("<L", len(entry[2])))
        fp.write(entry[2] + '\0')
