package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Opts struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

type PrivateKey struct {
	BitSize int
	Path    string
	Blob    Blob
}

type PublicKey struct {
	Blob Blob
	Path string
}

type Blob struct {
	File *os.File
	Data []byte
}

// Create generate temporary public & private RSA Key
func (opts *Opts) Create() error {
	var (
		err error
	)

	if opts.PrivateKey.Path == "" {
		opts.PrivateKey.Blob.File, err = ioutil.TempFile(os.TempDir(), "PrivateKey-*")
		if err != nil {
			return errors.Wrap(err, err.Error())
		}

		opts.PrivateKey.Path = opts.PrivateKey.Blob.File.Name()
	}

	if opts.PublicKey.Path == "" {
		opts.PublicKey.Blob.File, err = ioutil.TempFile(os.TempDir(), "PublicKey-*.pub")
		if err != nil {
			return errors.Wrap(err, err.Error())
		}

		opts.PublicKey.Path = opts.PublicKey.Blob.File.Name()
	}

	key, err := opts.privateKey(opts.PrivateKey.BitSize)
	if err != nil {
		return errors.Wrap(err, err.Error())
	}

	err = opts.publicKey(&key.PublicKey)
	if err != nil {
		return errors.Wrap(err, err.Error())
	}

	for _, b := range []Blob{
		opts.PrivateKey.Blob,
		opts.PublicKey.Blob,
	} {
		if err = ioutil.WriteFile(b.File.Name(), b.Data, os.ModePerm); err != nil {
			return errors.Wrap(err, err.Error())
		}
		defer b.File.Close()
	}

	return nil
}

func (opts *Opts) privateKey(bitsize int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, err
	}

	err = key.Validate()
	if err != nil {
		return nil, err
	}

	opts.PrivateKey.Blob.Data = opts.encodePrivateKey(key)

	return key, nil
}

func (opts *Opts) publicKey(pvKey *rsa.PublicKey) error {
	key, err := ssh.NewPublicKey(pvKey)
	if err != nil {
		return err
	}

	opts.PublicKey.Blob.Data = ssh.MarshalAuthorizedKey(key)

	return nil
}

func (opts *Opts) encodePrivateKey(pvKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Bytes: x509.MarshalPKCS1PrivateKey(pvKey)})
}
