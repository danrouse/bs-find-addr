document.addEventListener('DOMContentLoaded', async () => {
    const spinner = document.getElementById('spinner');
    spinner.style.display = 'block';

    const metadata = await fetch('./metadata.json').then(res => res.json());
    const thunks = await fetch('./thunks.json').then(res => res.json());

    spinner.style.display = 'none';

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
        return line.replace(/pc ([0-9a-f]+)  [\S]+libil2cpp\.so /, (match, addr) =>
            `${match} [ ${getMethodSignatureForAddress(parseInt(addr, 16))} ] `);
    }

    document.getElementById('input').addEventListener('change', (event) => {
        document.getElementById('output').innerHTML = '<pre>' +
            event.currentTarget.value.split('\n').map(line => processLine(line)).join('\n') +
            '</pre>';
    });
});
