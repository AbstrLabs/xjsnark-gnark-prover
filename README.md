# xjsnark-gnark-prover

This repo implements a [gnark](https://github.com/ConsenSys/gnark) backend to compile and prove a zk-SNARK circuit defined in [xjsnark](https://github.com/akosba/xjsnark) framework.


## Build
```
go build
```

### Use
```
./xjsnark-gnark-prover compile <arith-circuit> <output-gnark-circuit>
./xjsnark-gnark-prover keygen <gnark-circuit> <output-pk> <output-vk>
./xjsnark-gnark-prover prove <gnark-circuit> <pk> <input> <output-proof>
./xjsnark-gnark-prover verify <proof> <vk> <public-input>
```


There is a couple of circuit and sample input in `test-cases/`, for example, for the aes128 circuit, `<arith-circuit>` is `test-cases/AES128.arith` and `<input>` is `test-cases/aes128-input.in`.
