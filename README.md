# File Structure
VKSA^*/

├── README.md                                       //  introduction
├── common                                          //  some Parameter
│   ├── config.h                                    
│   ├── data_type_enclave.h
│   └── data_type.h
├── CryptoEnclave                                   //  Trusted part
│   ├── CryptoEnclave_t.c                           //  Trusted part class 
│   ├── CryptoEnclave_t.h   
│   ├── EnclaveUtil.h                               //  Trusted Util class
│   └── EnclaveUtil.cpp
├── CryptoTestingApp                                //  Untrusted part
│   ├── CryptoEnclave_u.c                           //  Trusted part class
│   ├── CryptoEnclave_u.h                           
│   ├── EnclaveUtil.h                               //  UnTrusted Util class
│   ├── EnclaveUtil.cpp               
│   ├── CryptoTestingApp.cpp                        //  main
│   ├── Data_Owner.h                                //  DataOwner class  
│   ├── Data_Owner.cpp                                    
│   ├── Data_User.h                                 //  DataUser class  
│   ├── Data_User.cpp                               
│   ├── Utils.cpp                                   //  Untrusted Util class
│   └── Utils.h
├── Exceptions
│   └── Exceptions.h                                //  Exceptions.h
└── Makefile
# Datasets
Email-enron: https://www.cs.cmu.edu/./enron/

# Prepare Environment
C++11
Install Intel(R) SGX SDK for Linux* OS
openssl
crypto
gmp

# Building Procedure
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd SE_SGX_1 && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
