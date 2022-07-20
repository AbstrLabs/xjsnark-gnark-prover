module github.com/abstrlabs/xjsnark-gnark-prover

go 1.17

require (
	github.com/consensys/gnark v0.7.1
	github.com/consensys/gnark-crypto v0.7.0
)

replace github.com/consensys/gnark => github.com/abstrlabs/gnark v0.6.5-0.20220720142728-a18617ccbd82

require (
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20220321153916-2c7772ba3064 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
