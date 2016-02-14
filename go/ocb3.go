// Package ocb3 is a Go binding to the OCB3 reference implementation in C.
// It is an implementation of crypto/cipher.AEAD, performing message
// authentication and encryption (AE) in one, supporting authentication of
// additional data (AD) that is not being encrypted.
package ocb3

// #define OCB_KEY_LEN 0
// #define OCB_TAG_LEN 0
// #define OCB_AES_IMPL 2
// #include "../ocb.c"
// #include "../rijndael-alg-fst.c"
// #cgo amd64 CFLAGS: -maes -mssse3
import "C"
import (
	"crypto/cipher"
	"errors"
	"fmt"
	"unsafe"
)

var (
	ErrInvalid      = errors.New("authentication failure")
	ErrNotSupported = errors.New("unsupported option")
)

// AESInfoString is a human readable description of what AES implementation
// is used.
var AESInfoString = C.GoString(&C.infoString[0])

// ctx is a wrapper for the ae_ctx C struct.
type ctx struct {
	impl  C.ae_ctx
	tsize int
}

type AEAD interface {
	cipher.AEAD
	Clear()
}

// New creates a new AEAD context backed by OCB3. The key must be 128, 192 or
// 256 bits. Nonce size is fixed to 12 bytes due to limitations in ocb.c. Tag
// size can range from 1 to 16 and defaults to 16. Returns error if input
// parameters are invalid.
func New(key []byte, os ...Opt) (AEAD, error) {
	ret := &ctx{tsize: 16}
	for _, o := range os {
		if err := o(ret); err != nil {
			return nil, err
		}
	}

	// ae_clear does not deallocate anything, so no need to call it.
	err := toError(C.ae_init((*C.ae_ctx)(&ret.impl), unsafe.Pointer(&key[0]), C.int(len(key)), C.int(12), C.int(ret.tsize)))
	return ret, err
}

// Opt is an option to change the behavior of New.
type Opt func(*ctx) error

// TagSize is an option to change the emitted/accepted tag size. Range 1 to 16.
func TagSize(n int) Opt {
	return func(c *ctx) error {
		c.tsize = n
		return nil
	}
}

// NonceSize returns the expected size of nonces.
func (c *ctx) NonceSize() int {
	return 12
}

// Overhead is the size of the authentication tag.
func (c *ctx) Overhead() int {
	return c.tsize
}

// Clear uses memset to clear the context. This may have some benefits in
// keeping secrets, but provides no guarantees.
func (c *ctx) Clear() {
	C.ae_clear((*C.ae_ctx)(&c.impl))
}

// Seal encrypts and signs the plaintext. Nonce is a random string that
// should never be reused for a given key and plaintext. Data is additional
// data that will be covered by the signature, but not be part of the encrypted
// data. Appends len(plaintext)+c.Overhead() bytes to dst and returns the new
// slice.
func (c *ctx) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != c.NonceSize() {
		panic(fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.NonceSize()))
	}

	nct := len(plaintext) + c.Overhead()
	lendst := len(dst)
	if len(dst)+nct > cap(dst) {
		dst2 := make([]byte, len(dst)+nct)
		copy(dst2, dst)
		dst = dst2
	} else {
		dst = dst[:lendst+nct]
	}

	var nptr unsafe.Pointer
	if len(nonce) > 0 {
		nptr = unsafe.Pointer(&nonce[0])
	}
	var pptr unsafe.Pointer
	if len(plaintext) > 0 {
		pptr = unsafe.Pointer(&plaintext[0])
	}
	var dptr unsafe.Pointer
	if len(data) > 0 {
		dptr = unsafe.Pointer(&data[0])
	}
	n := C.ae_encrypt((*C.ae_ctx)(&c.impl), nptr, pptr, C.int(len(plaintext)), dptr, C.int(len(data)), unsafe.Pointer(&dst[lendst]), nil, C.AE_FINALIZE)
	if n < 0 {
		panic(toError(n))
	}

	if int(n) != nct {
		panic(fmt.Errorf("ae_encrypt: got %d bytes, want %d bytes", n, nct))
	}
	return dst
}

// Open authenticates and decrypts the ciphertext. Nonce and data must be
// the same that were provided to Seal. Appends len(ciphertext)-c.Overhead()
// bytes to dst and returns the new slice.
func (c *ctx) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.NonceSize())
	}

	// Pad with one byte to avoid dst[lendst] panicking
	// if npt == 0.
	npt := len(ciphertext) - c.Overhead()
	lendst := len(dst)
	if len(dst)+npt+1 > cap(dst) {
		dst2 := make([]byte, len(dst)+npt+1)
		copy(dst2, dst)
		dst = dst2
	} else {
		dst = dst[:lendst+npt+1]
	}

	var nptr unsafe.Pointer
	if len(nonce) > 0 {
		nptr = unsafe.Pointer(&nonce[0])
	}
	var cptr unsafe.Pointer
	if len(ciphertext) > 0 {
		cptr = unsafe.Pointer(&ciphertext[0])
	}
	var dptr unsafe.Pointer
	if len(data) > 0 {
		dptr = unsafe.Pointer(&data[0])
	}
	n := C.ae_decrypt((*C.ae_ctx)(&c.impl), nptr, cptr, C.int(len(ciphertext)), dptr, C.int(len(data)), unsafe.Pointer(&dst[lendst]), nil, C.AE_FINALIZE)
	if n < 0 {
		return nil, toError(n)
	}

	if int(n) != npt {
		panic(fmt.Errorf("ae_decrypt: got %d bytes, want %d bytes", n, npt))
	}
	return dst[:len(dst)-1], nil
}

// toError converts an AE_* error code to a Go error. Returns nil for
// AE_SUCCESS.
func toError(status C.int) error {
	switch status {
	case C.AE_SUCCESS:
		return nil
	case C.AE_INVALID:
		return ErrInvalid
	case C.AE_NOT_SUPPORTED:
		return ErrNotSupported
	default:
		return fmt.Errorf("unknown OCB3 error: %d", status)
	}
}
