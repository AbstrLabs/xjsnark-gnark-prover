package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Errorf("Usage: prover arith input")
		os.Exit(1)
	}
	log.Print("Start Loading and compiling Xjsnark arith file")

	circuit := newCircuitFromXjsnark(os.Args[1])

	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	log.Print("Load and compile Xjsnark arith file done")

	pk, vk, err := groth16.Setup(r1cs)
	log.Print("Generate pk and vk done")

	assignment := loadAssignment(os.Args[2], circuit)
	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	publicWitness, _ := witness.Public()
	log.Print("Load witness done")

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}
	log.Print("Prove done")

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	log.Print("Verify done")
}

type Circuit struct {
	P         []frontend.Variable `gnark:",public"`
	S         []frontend.Variable
	outputEnd uint
	Scanner   *bufio.Scanner
	totalVars uint
}

func (circuit *Circuit) Define(api frontend.API) error {
	parseLibsnarkArith(circuit, api)
	return nil
}

func sliceAtoi(sa []string) ([]int, error) {
	si := make([]int, 0, len(sa))
	for _, a := range sa {
		i, err := strconv.Atoi(a)
		if err != nil {
			return si, err
		}
		si = append(si, i)
	}
	return si, nil
}

func newCircuitFromXjsnark(xjsnarkArithPath string) (circuit *Circuit) {
	circuit = new(Circuit)
	f, err := os.Open(xjsnarkArithPath)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	circuit.Scanner = scanner

	scanner.Scan()
	line := scanner.Text()
	n, _ := fmt.Sscanf(line, "total %d", &circuit.totalVars)
	if n != 1 {
		log.Fatal("File Format Does not Match, expect total n")
	}
	var nPublicInput, nSecretInput uint
	for scanner.Scan() {
		line = scanner.Text()

		var id uint
		n, _ = fmt.Sscanf(line, "input %d", &id)
		if n == 1 {
			nPublicInput++
			continue
		}

		n, _ = fmt.Sscanf(line, "nizkinput %d", &id)
		if n == 1 {
			nSecretInput++
			continue
		}

		// gnark does not support output, we record the ids and just log them in the end
		n, _ = fmt.Sscanf(line, "output %d", &id)
		if n == 1 {
			circuit.outputEnd = id
			continue
		}

		break
	}

	circuit.P = make([]frontend.Variable, nPublicInput)
	circuit.S = make([]frontend.Variable, nSecretInput)
	return
}

func parseLibsnarkArith(circuit *Circuit, api frontend.API) {
	Vars := make([]frontend.Variable, circuit.totalVars)
	scanner := circuit.Scanner

	for i, p := range circuit.P {
		Vars[i] = p
	}
	for i, s := range circuit.S {
		Vars[i+len(circuit.P)] = s
	}

	for {
		line := scanner.Text()
		var t, inStr, outStr string
		n, _ := fmt.Sscanf(line, "%s in %s out %s", &t, &inStr, &outStr)
		if n == 3 {
			inValues, err := sliceAtoi(strings.Split(inStr, "_"))
			if err != nil {
				log.Fatal(err)
			}
			outValues, err := sliceAtoi(strings.Split(outStr, "_"))
			if err != nil {
				log.Fatal(err)
			}

			if t == "add" {
				var in []frontend.Variable
				if len(inValues) > 2 {
					in = make([]frontend.Variable, len(inValues)-2)
					for i := 2; i < len(inValues); i++ {
						in[i-2] = Vars[inValues[i]]
					}
				} else {
					in = make([]frontend.Variable, 0)
				}
				Vars[outValues[0]] = api.Add(Vars[inValues[0]], Vars[inValues[1]], in...)
			} else if t == "mul" {
				Vars[outValues[0]] = api.Mul(Vars[inValues[0]], Vars[inValues[1]])
			} else if strings.Contains(t, "const-mul-neg-") {
				constStr := t[len("const-mul-neg-"):]
				bi, success := new(big.Int).SetString(constStr, 16)
				if !success {
					log.Fatal("not a valid hex number")
				}
				Vars[outValues[0]] = api.Mul(api.Neg(bi), Vars[inValues[0]])
			} else if strings.Contains(t, "const-mul-") {
				constStr := t[len("const-mul-"):]
				bi, success := new(big.Int).SetString(constStr, 16)
				if !success {
					log.Fatal("not a valid hex number. line:", line)
				}
				Vars[outValues[0]] = api.Mul(bi, Vars[inValues[0]])
			} else if t == "assert" {
				api.AssertIsEqual(api.Mul(Vars[inValues[0]], Vars[inValues[1]]), Vars[outValues[0]])
			} else if t == "xor" {
				Vars[outValues[0]] = api.Xor(api.IsZero(Vars[inValues[0]]), api.IsZero(Vars[inValues[1]]))
			} else if t == "or" {
				Vars[outValues[0]] = api.IsZero(api.And(api.IsZero(Vars[inValues[0]]), api.IsZero(Vars[inValues[1]])))
			} else if t == "zerop" {
				Vars[outValues[1]] = api.Sub(big.NewInt(1), api.IsZero(Vars[inValues[0]]))
			} else if t == "split" {
				l := len(outValues)
				if l == 1 {
					Vars[outValues[0]] = Vars[inValues[0]]
				} else {
					bits := api.ToBinary(Vars[inValues[0]], l)
					for i, e := range bits {
						Vars[outValues[i]] = e
					}
				}
			} else if t == "pack" {
				in := make([]frontend.Variable, len(inValues))
				for i := 0; i < len(inValues); i++ {
					in[i] = Vars[inValues[i]]
				}
				Vars[outValues[0]] = api.FromBinary(in...)
			} else {
				log.Fatal("Unknown opcode:", t)
			}

		} else {
			log.Fatal("Arith file format invalid line:", line, "expected <opcode> in <input vars> out <output vars>")
		}
		if !scanner.Scan() {
			break
		}
	}

	if circuit.outputEnd != 0 {
		outputStart := len(circuit.P) + len(circuit.S)
		for i := outputStart; i <= int(circuit.outputEnd); i++ {
			api.Println("Output", i, "=", Vars[i])
		}
	}

	// For debug purpose, log all var
	// for i := 0; i < int(circuit.totalVars); i++ {
	// 	api.Println(i, Vars[i])
	// }

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func loadAssignment(filename string, circuit *Circuit) (ret *Circuit) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	ret = new(Circuit)
	ret.outputEnd = circuit.outputEnd
	ret.P = make([]frontend.Variable, len(circuit.P))
	ret.S = make([]frontend.Variable, len(circuit.S))

	var id int
	var hex string

	for {
		n, _ := fmt.Fscanf(f, "%d %s\n", &id, &hex)

		if n != 2 {
			break
		}
		bi, success := new(big.Int).SetString(hex, 16)
		if !success {
			log.Fatal("not a valid hex number")
		}
		if id < len(ret.P) {
			ret.P[id] = bi
		} else if id < len(ret.P)+len(ret.S) {
			ret.S[id-len(ret.P)] = bi
		}
	}
	return
}
