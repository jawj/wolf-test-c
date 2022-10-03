
Module.onRuntimeInitialized = function() {
  console.log('Running ...');

  // int(*jsProvideEncryptedFromNetwork)(char *buff, int maxSize);
  // void(*jsReceiveDecryptedFromLibrary)(char *buff, int size);
  // int(*jsWriteEncryptedToNetwork)(char *buff, int size);

  function provideEncryptedFromNetwork(buff, maxSize) {
    console.log(`providing up to ${maxSize} encrypted bytes from network`);
  }

  function receiveDecryptedFromLibrary(buff, size) {
    console.log(`receiving ${size} decrypted bytes from library`);
  }

  function writeEncryptedToNetwork(buff, size) {
    console.log(`writing ${size} encrypted bytes to network`);
    return size;
  }

  const 
  ptrProvideEncryptedFromNetwork = Module.addFunction(provideEncryptedFromNetwork, 'iii'),
  ptrReceiveDecryptedFromLibrary = Module.addFunction(receiveDecryptedFromLibrary, 'vii'),
  ptrWriteEncryptedToNetwork = Module.addFunction(writeEncryptedToNetwork, 'iii');

  Module.ccall('init',  // name of C function
    null, // return type (void)
    ['number', 'number', 'number'],  // argument types (pointers)
    [ptrProvideEncryptedFromNetwork, ptrReceiveDecryptedFromLibrary, ptrWriteEncryptedToNetwork],  // arguments
  );

  const result = Module.ccall('handshake',  // name of C function
    'number',  // return type
    ['string', 'string'],  // argument types
    ['neon.tech', '443'],  // arguments
  ); 

  console.log(result);
}
