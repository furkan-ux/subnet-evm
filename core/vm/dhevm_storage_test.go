package vm

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/ava-labs/dhe-core/hpbfv"
	"github.com/ava-labs/dhe-core/ring"
	"github.com/ava-labs/dhe-core/rlwe"
	"github.com/ava-labs/dhe-core/utils"
	"github.com/ava-labs/subnet-evm/core/rawdb"
	"github.com/ava-labs/subnet-evm/core/state"
	"github.com/ava-labs/subnet-evm/core/types"
	"github.com/ava-labs/subnet-evm/params"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
)

func setupTestEVM(t *testing.T) *EVM {
	vmctx := BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(0),
	}
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	return NewEVM(vmctx, TxContext{}, statedb, params.TestSubnetEVMChainConfig, Config{})
}

func TestDhevmStorage(t *testing.T) {
	// Setup
	evm := setupTestEVM(t)
	storage := NewDHEvmStorage(evm)
	params := hpbfv.NewParametersFromLiteral(hpbfv.DHEN13D7T1024)
	ctx, err := generateTestContext(params)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Basic Storage Operations", func(t *testing.T) {
		ct, testID := generateRandomCiphertext(ctx, t)

		assert.False(t, storage.isCiphertextPersisted(testID))
		assert.False(t, storage.isCiphertextLoaded(testID))

		storage.insertCiphertextToStorage(ct)
		assert.True(t, storage.isCiphertextPersisted(testID))

		metadata := storage.loadCiphertextMetadata(testID)
		assert.NotNil(t, metadata)
		assert.Greater(t, metadata.chunks, uint64(0))

		loadedCt, err := storage.loadCiphertext(testID)
		assert.NoError(t, err)
		assert.NotNil(t, loadedCt)
		assert.True(t, loadedCt.MetaData.Equal(ct.MetaData))

		storage.insertCiphertextToMemoryWithId(testID, ct)
		assert.True(t, storage.isCiphertextLoaded(testID))

		memCt := storage.GetCiphertextFromMemory(testID)
		assert.NotNil(t, memCt)

		loadedCts := storage.GetLoadedCiphertexts()
		assert.Contains(t, loadedCts, testID)
	})

	t.Run("Double Store Operation", func(t *testing.T) {
		ct, testID := generateRandomCiphertext(ctx, t)

		// Store the same ciphertext twice
		storage.insertCiphertextToStorage(ct)
		metadata1 := storage.loadCiphertextMetadata(testID)

		storage.insertCiphertextToStorage(ct)
		metadata2 := storage.loadCiphertextMetadata(testID)

		// Metadata should be identical
		assert.Equal(t, metadata1.chunks, metadata2.chunks)
	})

	t.Run("Load Non-Existent Ciphertext", func(t *testing.T) {
		nonExistentID := common.HexToHash("0x1234")
		loadedCt, err := storage.loadCiphertext(nonExistentID)
		assert.Nil(t, err)
		assert.Nil(t, loadedCt)
	})

	t.Run("Memory Cache Operations", func(t *testing.T) {
		ct, testID := generateRandomCiphertext(ctx, t)

		// Store in memory first
		storage.insertCiphertextToStorage(ct)

		// Load should return cached version without touching storage
		loadedCt, err := storage.loadCiphertext(testID)
		assert.NoError(t, err)
		assert.NotNil(t, loadedCt)
		assert.True(t, loadedCt.MetaData.Equal(ct.MetaData))

		// Verify it's the same instance from cache
		assert.True(t, ct.MetaData.Equal(loadedCt.MetaData))
	})

	t.Run("Multiple Ciphertexts", func(t *testing.T) {
		// Store multiple ciphertexts
		numCiphertexts := 3
		ciphertexts := make([]*hpbfv.Ciphertext, numCiphertexts)
		ids := make([]common.Hash, numCiphertexts)

		for i := 0; i < numCiphertexts; i++ {
			ct, id := generateRandomCiphertext(ctx, t)
			ciphertexts[i] = ct
			ids[i] = id
			storage.insertCiphertextToStorage(ct)
		}

		// Verify each can be loaded correctly
		for i := 0; i < numCiphertexts; i++ {
			loadedCt, err := storage.loadCiphertext(ids[i])
			assert.NoError(t, err)
			assert.NotNil(t, loadedCt)
			assert.True(t, loadedCt.MetaData.Equal(ciphertexts[i].MetaData))
		}
	})

	t.Run("Metadata Operations", func(t *testing.T) {
		ct, testID := generateRandomCiphertext(ctx, t)

		// Store and get metadata
		storage.insertCiphertextToStorage(ct)
		metadata := storage.loadCiphertextMetadata(testID)

		// Verify metadata calculations
		expectedChunks := (uint64(ct.MarshalBinarySize()) + 31) / 32
		assert.Equal(t, expectedChunks, metadata.chunks)

		// Test metadata serialization/deserialization
		serialized := metadata.serialize()
		deserialized := &ctMetadata{}
		deserialized.deserialize(serialized)
		assert.Equal(t, metadata.chunks, deserialized.chunks)
	})
}

type dheTestContext struct {
	params    hpbfv.Parameters
	ringQ     *ring.Ring
	prng      utils.PRNG
	uSampler  *ring.UniformSampler
	kgen      hpbfv.KeyGenerator
	sk        *rlwe.SecretKey
	pk        *rlwe.PublicKey
	rlk       *rlwe.RelinearizationKey
	rtks      *rlwe.RotationKeySet
	encoder   *hpbfv.Encoder
	decoder   *hpbfv.Decoder
	encryptor *hpbfv.Encryptor
	decryptor *hpbfv.Decryptor
	eval      *hpbfv.Evaluator
}

func generateTestContext(params hpbfv.Parameters) (testCtx *dheTestContext, err error) {
	testCtx = new(dheTestContext)
	testCtx.params = params

	if testCtx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testCtx.ringQ = params.RingQ()
	testCtx.uSampler = ring.NewUniformSampler(testCtx.prng, testCtx.ringQ)
	testCtx.kgen = hpbfv.NewKeyGenerator(testCtx.params)

	testCtx.sk, testCtx.pk = testCtx.kgen.GenKeyPair()

	testCtx.rlk = testCtx.kgen.GenRelinearizationKey(testCtx.sk, 1)
	testCtx.rtks = testCtx.kgen.GenDefaultRotationKeysForRotation(testCtx.sk)

	testCtx.encoder = hpbfv.NewEncoder(testCtx.params)
	testCtx.decoder = hpbfv.NewDecoder(testCtx.params)

	testCtx.encryptor = hpbfv.NewEncryptor(testCtx.params, testCtx.pk)
	testCtx.decryptor = hpbfv.NewDecryptor(testCtx.params, testCtx.sk)

	testCtx.eval = hpbfv.NewEvaluator(testCtx.params)
	return
}

// function for generating a random ciphertext and its id
func generateRandomCiphertext(ctx *dheTestContext, t *testing.T) (*hpbfv.Ciphertext, common.Hash) {
	msg := randomVectors(ctx)
	ct := ctx.encryptor.EncryptMsgNew(msg)
	// hash ct with keccak256 to get a ciphertext id
	data, err := ct.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	ciphertextId := common.Hash(sha256.Sum256(data))
	return ct, ciphertextId
}

func randomVectors(ctx *dheTestContext) (msg *hpbfv.Message) {
	params := ctx.params
	coeffs := ctx.uSampler.ReadNew()
	msg = hpbfv.NewMessage(params)
	ctx.ringQ.PolyToBigint(coeffs, params.N()/params.Slots(), msg.Value)

	for i := 0; i < params.Slots(); i++ {
		msg.Value[i].Mod(msg.Value[i], params.T())
	}
	return
}
