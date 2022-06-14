# xjsnark-gnark-prover

This repo implements a [gnark](https://github.com/ConsenSys/gnark) backend to compile and prove a zk-SNARK circuit defined in [xjsnark](https://github.com/akosba/xjsnark) framework.


## Build
```
go build
```

### Use
```
./xjsnark-gnark-prover circuit input
```

There is a couple of circuit and sample input in `test-cases/`, for example: 
```
./xjsnark-gnark-prover test-cases/AES128.arith test-cases/aes128-input.in
``` 