const fs = require('fs');
const IL2CPPINSPECTOR_METADATA_JSON_PATH = process.env.METADATA_JSON || "./metadata.json";
const GHIDRA_THUNKS_JSON_PATH = process.env.THUNKS_JSON || "./thunks.json";

const metadata = JSON.parse(fs.readFileSync(IL2CPPINSPECTOR_METADATA_JSON_PATH));
const thunks = JSON.parse(fs.readFileSync(GHIDRA_THUNKS_JSON_PATH));
const methodDefinitions = [].concat(
        metadata.addressMap.methodDefinitions,
        metadata.addressMap.constructedGenericMethods,
        // metadata.addressMap.customAttributesGenerators,
        metadata.addressMap.apis,
        thunks
    )
    .filter(def => def.virtualAddress.length === 10)
    .map(def => [parseInt(def.virtualAddress), def.signature])
    .sort((a, b) => a[0] - b[0]);

const os = fs.createWriteStream('./addrs.bin');
methodDefinitions.forEach(([addr, sig]) => {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32LE(addr);
    os.write(buf);
    os.write(sig);
    os.write(Buffer.from([0x00]));
});
os.end();
