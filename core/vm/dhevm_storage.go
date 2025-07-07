package vm

import (
	"crypto/sha256"

	"github.com/ava-labs/dhe-core/hpbfv"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

// pre-allocated storage address for the DHEVM storage
var DHEvmStorageAddress = common.HexToAddress("0x5000000000000000000000000000000000000000")

type ctMetadata struct {
	chunks uint64 // amount of the 32-byte chunks in the ciphertext
}

// serializes the ctMetadata into a 32-byte array
func (mt *ctMetadata) serialize() [32]byte {
	u := uint256.NewInt(0)
	u[0] = mt.chunks
	return u.Bytes32()
}

// deserializes the 32-byte array into a ctMetadata
func (mt *ctMetadata) deserialize(buff [32]byte) *ctMetadata {
	u := uint256.NewInt(0)
	u.SetBytes(buff[:])
	mt.chunks = u[0]
	return mt
}

// creates a new ctMetadata from a 32-byte array
func newCiphertextMetadata(buff [32]byte) *ctMetadata {
	mt := &ctMetadata{}
	return mt.deserialize(buff)
}

type DHEvmStorage struct {
	// evm
	evm *EVM
	// storage is the storage for the DHE ciphertexts
	// mapping for in memory ciphertexts
	inMemoryCiphertexts map[common.Hash]*hpbfv.Ciphertext
	// params
	params hpbfv.Parameters
}

func NewDHEvmStorage(evm *EVM) *DHEvmStorage {
	log.Info("Creating new DHEvmStorage instance with params", "params", hpbfv.DHEN13D7T1024)
	params := hpbfv.NewParametersFromLiteral(hpbfv.DHEN13D7T1024)
	return &DHEvmStorage{
		evm:                 evm,
		inMemoryCiphertexts: make(map[common.Hash]*hpbfv.Ciphertext),
		params:              params,
	}
}

// gets the ciphertext from the memory
func (dhevm *DHEvmStorage) GetCiphertextFromMemory(ciphertextId common.Hash) *hpbfv.Ciphertext {
	log.Info("Getting ciphertext from memory", "ciphertextId", ciphertextId)
	if ct, ok := dhevm.inMemoryCiphertexts[ciphertextId]; ok {
		log.Info("Ciphertext found in memory", "ciphertextId", ciphertextId)
		return ct
	}
	return nil
}

func (dhevm *DHEvmStorage) GetLoadedCiphertexts() map[common.Hash]*hpbfv.Ciphertext {
	return dhevm.inMemoryCiphertexts
}

// checks if the ciphertext is persisted in the storage
func (dhevm *DHEvmStorage) isCiphertextPersisted(ciphertextId common.Hash) bool {
	metadataInt := uint256.NewInt(0).SetBytes(dhevm.evm.StateDB.GetState(DHEvmStorageAddress, ciphertextId).Bytes())
	isPersisted := !metadataInt.IsZero()
	log.Info("Checking if ciphertext is persisted", "ciphertextId", ciphertextId, "isPersisted", isPersisted)
	return isPersisted
}

// checks if the ciphertext is loaded in memory
func (dhevm *DHEvmStorage) isCiphertextLoaded(ciphertextId common.Hash) bool {
	log.Info("Checking if ciphertext is loaded", "ciphertextId", ciphertextId)
	return dhevm.inMemoryCiphertexts[ciphertextId] != nil
}

// loads the ciphertext metadata from the storage
func (dhevm *DHEvmStorage) loadCiphertextMetadata(ciphertextId common.Hash) *ctMetadata {
	metadataInt := uint256.NewInt(0).SetBytes(dhevm.evm.StateDB.GetState(DHEvmStorageAddress, ciphertextId).Bytes())
	if metadataInt.IsZero() {
		return nil
	}
	return newCiphertextMetadata(metadataInt.Bytes32())
}

// stores the metadata in the storage
func (dhevm *DHEvmStorage) storeMetadata(ciphertextId common.Hash, metadata *ctMetadata) {
	buff := metadata.serialize()
	dhevm.evm.StateDB.SetState(DHEvmStorageAddress, ciphertextId, buff)
}

// gets the metadata from the storage
func (dhevm *DHEvmStorage) getMetadataFromStorage(ciphertextId common.Hash) *ctMetadata {
	buff := dhevm.evm.StateDB.GetState(DHEvmStorageAddress, ciphertextId).Bytes()
	if len(buff) == 0 {
		return nil
	}
	return newCiphertextMetadata(common.BytesToHash(buff))
}

// inserts the ciphertext into the memory
func (dhevm *DHEvmStorage) insertCiphertextToMemory(ct *hpbfv.Ciphertext) (common.Hash, error) {
	ciphertextId := GetCiphertextId(ct)
	dhevm.insertCiphertextToMemoryWithId(ciphertextId, ct)
	return ciphertextId, nil
}

// inserts the ciphertext into the memory
func (dhevm *DHEvmStorage) insertCiphertextToMemoryWithId(ciphertextId common.Hash, ct *hpbfv.Ciphertext) {
	log.Info("Inserting ciphertext to memory", "ciphertextId", ciphertextId)
	dhevm.inMemoryCiphertexts[ciphertextId] = ct
}

// inserts the ciphertext into the storage with a given id
func (dhevm *DHEvmStorage) insertCiphertextToStorageWithId(ciphertextId common.Hash, ct *hpbfv.Ciphertext) error {
	if dhevm.isCiphertextPersisted(ciphertextId) {
		return nil
	}

	metadata := &ctMetadata{}
	totalSize := ct.MarshalBinarySize()
	metadata.chunks = uint64((totalSize + 31) / 32) // 32 bytes per chunk (+31 for rounding up)

	// store the metadata
	dhevm.storeMetadata(ciphertextId, metadata)

	initialSlot := uint256.NewInt(0).SetBytes(ciphertextId.Bytes())
	initialSlot.AddUint64(initialSlot, 1) // +1 for the metadata

	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		log.Error("Error marshalling ciphertext", "err", err)
		return err
	}

	ctChunk := make([]byte, 32)
	chunkIndex := 0
	for i, b := range ctBytes {
		if i%32 == 0 && i != 0 {
			// store the chunk
			dhevm.evm.StateDB.SetState(DHEvmStorageAddress, initialSlot.Bytes32(), common.BytesToHash(ctChunk))

			// move to next slot
			initialSlot.AddUint64(initialSlot, 1)
			ctChunk = make([]byte, 32)
			chunkIndex = 0
		}
		ctChunk[chunkIndex] = b
		chunkIndex++
	}

	// store any remaining bytes in the last chunk
	if len(ctChunk) != 0 {
		dhevm.evm.StateDB.SetState(DHEvmStorageAddress, initialSlot.Bytes32(), common.BytesToHash(ctChunk))
	}
	return nil
}

// inserts the ciphertext into the storage
func (dhevm *DHEvmStorage) insertCiphertextToStorage(ct *hpbfv.Ciphertext) (common.Hash, error) {
	ciphertextId := GetCiphertextId(ct)
	log.Info("Inserting ciphertext to storage", "ciphertextId", ciphertextId)
	err := dhevm.insertCiphertextToStorageWithId(ciphertextId, ct)
	return ciphertextId, err
}

// loads the ciphertext from the storage
func (dhevm *DHEvmStorage) loadCiphertext(ciphertextId common.Hash) (*hpbfv.Ciphertext, error) {
	log.Info("Loading ciphertext from storage", "ciphertextId", ciphertextId)
	metadata := dhevm.loadCiphertextMetadata(ciphertextId)
	if metadata == nil {
		return nil, nil
	}

	// check if the ciphertext is already loaded in memory
	ct, ok := dhevm.inMemoryCiphertexts[ciphertextId]
	if ok {
		return ct, nil
	}

	// Initialize starting slot after metadata
	slot := uint256.NewInt(0).SetBytes(ciphertextId.Bytes())
	slot.AddUint64(slot, 1) // Start after metadata

	// Create a temporary ciphertext to get the actual size
	tempCt := hpbfv.NewCiphertext(dhevm.params, 1)
	actualSize := tempCt.MarshalBinarySize()

	// Read all chunks
	ctBytes := make([]byte, 0, metadata.chunks*32)
	for i := uint64(0); i < metadata.chunks; i++ {
		chunk := dhevm.evm.StateDB.GetState(DHEvmStorageAddress, slot.Bytes32()).Bytes()

		// for the last chunk, need to handle the partial chunk
		if i == metadata.chunks-1 && actualSize%32 != 0 {
			lastChunkSize := actualSize % 32
			ctBytes = append(ctBytes, chunk[:lastChunkSize]...)
		} else {
			ctBytes = append(ctBytes, chunk...)
		}
		slot.AddUint64(slot, 1)
	}

	// unmarshal the ciphertext
	ct = hpbfv.NewCiphertext(dhevm.params, 1)
	err := ct.UnmarshalBinary(ctBytes)
	if err != nil {
		return nil, err
	}

	dhevm.insertCiphertextToMemoryWithId(ciphertextId, ct)

	return ct, nil
}

// loads 2 ciphertexts from the storage
func (dhevm *DHEvmStorage) load2Ciphertexts(cId1, cId2 common.Hash) ([]*hpbfv.Ciphertext, error) {
	log.Info("Loading 2 ciphertexts from storage", "cId1", cId1, "cId2", cId2)
	out := make([]*hpbfv.Ciphertext, 2)

	for i, ciphertextId := range []common.Hash{cId1, cId2} {
		ct, err := dhevm.loadCiphertext(ciphertextId)
		if err != nil {
			return nil, err
		}
		out[i] = ct
	}

	return out, nil
}

// gets the ciphertext id from the ciphertext
func GetCiphertextId(ct *hpbfv.Ciphertext) common.Hash {
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return common.Hash{}
	}
	h := sha256.New()
	h.Write(ctBytes)
	return common.BytesToHash(h.Sum(nil))
}
