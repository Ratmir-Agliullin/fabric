package main

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// DocHash Chaincode implementation
type DocChaincode struct {
}

var logger = shim.NewLogger("DocChaincode")

func (t *DocChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("Init")
	return shim.Success(nil)
}

func (t *DocChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {

	logger.Info("Invoke")

	function, args := stub.GetFunctionAndParameters()

	logger.Info(function, args)

	if function == "add" {
		// Add document, parameters: name, current_hash
		return t.add(stub, args)
	} else if function == "update" {
		// Update document, parameters: name, previous_hash, current_hash
		return t.update(stub, args)
	} else if function == "query" {
		// Get history of document changes, parameters: name
		return t.query(stub, args)
	}

	return shim.Error("Invalid invoke function name. Expecting \"add\" \"update\" \"query\".")
}

// add puts document into KVS, parameters: name, current_hash
func (t *DocChaincode) add(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting name of document and its hash.")
	}

	var Name, Hash string

	Name = args[0]
	Hash = args[1]

	hash, err := stub.GetState(Name)

	if err != nil {
		return shim.Error(err.Error())
	}

	if hash != nil {
		return shim.Error("File \"" + Name + "\" already exists with hash=" + string(hash))
	}

	err = stub.PutState(Name, []byte(Hash))
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// update puts new document hash into KVS, parameters: name, current_hash
func (t *DocChaincode) update(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting name of document and its previous hash and new hash.")
	}

	var Name, OldHash, NewHash string

	Name = args[0]
	OldHash = args[1]
	NewHash = args[2]

	CurrentHash, err := stub.GetState(Name)

	if err != nil {
		return shim.Error(err.Error())
	}

	if CurrentHash == nil {
		return shim.Error("File \"" + Name + "\" doesnt exist in storage.")
	}

	if string(CurrentHash) != OldHash {
		return shim.Error("File \"" + Name + "\" has another hash=" + string(CurrentHash))
	}

	err = stub.PutState(Name, []byte(NewHash))
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// query gets history of document changes from KVS, parameters: name
func (t *DocChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of document.")
	}

	var Name string
	var err error

	Name = args[0]

	resultsIterator, err := stub.GetHistoryForKey(Name)
	if err != nil {
		shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	// buffer is a JSON array containing historic values
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			shim.Error(err.Error())
		}

		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"TxId\":")
		buffer.WriteString("\"")
		buffer.WriteString(response.TxId)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Value\":")

		// If it was a delete operation on given key, then we need to set the corresponding value null.
		// Else, we will write the response.Value as-is
		if response.IsDelete {
			buffer.WriteString("null")
		} else {
			buffer.WriteString(string(response.Value))
		}

		buffer.WriteString(", \"Timestamp\":")
		buffer.WriteString("\"")
		buffer.WriteString(time.Unix(response.Timestamp.Seconds, int64(response.Timestamp.Nanos)).String())
		buffer.WriteString("\"")

		buffer.WriteString(", \"IsDelete\":")
		buffer.WriteString("\"")
		buffer.WriteString(strconv.FormatBool(response.IsDelete))
		buffer.WriteString("\"")

		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}

	buffer.WriteString("]")

	return shim.Success(buffer.Bytes())
}

func main() {
	logger.Info("main")
	err := shim.Start(new(DocChaincode))
	if err != nil {
		fmt.Printf("Error starting doc chaincode: %s", err)
	}
}
