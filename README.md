# threshold-ECDSA
# Prerequsite
- install intel-sgx environment
- download sgx-gmp, sgx-ssl library
- edit sgx_tgmp.h especially comment out the file macro because it doesn't suit cpp, which is my understanding0.0
# Run
Simulator :
``` shell
cd (Node/Combiner/Setup) && make SGX_MODE=SIM
```
Hardware :
``` shell
cd (Node/Combiner/Setup) && make
```
run :
``` shell
. setup.sh && . run.sh
```
# Log file
After you run these app, you will find setuplog.txt, logi.txt, combiner.txt in the subdirectory.