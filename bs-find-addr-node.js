// change this or pass your own through env


function usage() {
    console.log('Usage: node bs-find-addr.js address');
    console.log('       node bs-find-addr.js logcat.txt');
    console.log('       adb logcat | node bs-find-addr.js');
    console.log('Requires metadata.json from Il2CppInspector and thunks.json (included)');
    console.log('Pass as METADATA_JSON=path THUNKS_JSON=path node bs-find-addr.js [...]');
}

const fs = require('fs');
const readline = require('readline');

// asynchronous programming is annoying so let's just not
const metadata = JSON.parse(fs.readFileSync(IL2CPPINSPECTOR_METADATA_JSON_PATH));
const thunks = JSON.parse(fs.readFileSync(GHIDRA_THUNKS_JSON_PATH));
const methodDefinitions = [].concat(
        metadata.addressMap.methodDefinitions,
        metadata.addressMap.constructedGenericMethods,
        metadata.addressMap.customAttributesGenerators,
        metadata.addressMap.apis,
        thunks
    )
    .map(def => [parseInt(def.virtualAddress), def.signature])
    .sort((a, b) => a[0] - b[0]);

const UNKNOWN_METHOD_SIGNATURE = "Unknown method";
function getMethodSignatureForAddress(address) {
    const index = methodDefinitions.findIndex(def => def[0] > address);
    if (index === -1) return UNKNOWN_METHOD_SIGNATURE;
    return methodDefinitions[index - 1][1];
}

function processLine(line) {
    console.log(line.replace(/pc ([0-9a-f]+)  [\S]+libil2cpp\.so /, (match, addr) =>
        `${match} [ ${getMethodSignatureForAddress(parseInt(addr, 16))} ] `));
}
function processErrorLine(line) {
    if (line.indexOf('AndroidRuntime') === -1) return;
    processLine(line);
}

if (process.argv[2]) {
    const address = parseInt(process.argv[2], 16);
    if (!Number.isNaN(address) && address.toString(16) === process.argv[2]) {
        // process single instruction address
        console.log('Method at address 0x' + address.toString(16) + ':', getMethodSignatureForAddress(address));
    } else {
        // read logcat from file
        const stream = fs.createReadStream(process.argv[2], { encoding: 'utf16le' });
        const rl = readline.createInterface(stream);
        rl.on('line', line => processErrorLine(line));
    }
} else if (!process.stdin.isTTY) {
    // read from stdin pipe
    process.stdin.setEncoding('utf-8');
    const rl = readline.createInterface({
        input: process.stdin
    });
    rl.on('line', line => processLine(line));
} else {
    usage();
}
