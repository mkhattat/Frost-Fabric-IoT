// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package frost implements FROST, the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol.
package frost

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/mkhattat/frost/dkg"
	"github.com/mkhattat/frost/internal"
)

// Ciphersuite identifies the group and hash to use for FROST.
type Ciphersuite byte

const (
	// Ed25519 uses Edwards25519 and SHA-512, producing Ed25519-compliant signatures as specified in RFC8032.
	Ed25519 Ciphersuite = 1 + iota

	// Ristretto255 uses Ristretto255 and SHA-512.
	Ristretto255

	// Ed448 uses Edwards448 and SHAKE256, producing Ed448-compliant signatures as specified in RFC8032.
	ed448

	// P256 uses P-256 and SHA-256.
	P256

	// Secp256k1 uses Secp256k1 and SHA-256.
	Secp256k1

	ed25519ContextString      = "FROST-ED25519-SHA512-v11"
	ristretto255ContextString = "FROST-RISTRETTO255-SHA512-v11"
	p256ContextString         = "FROST-P256-SHA256-v11"
	secp256k1ContextString    = "FROST-secp256k1-SHA256-v11"

	/*

		ed448ContextString        = "FROST-ED448-SHAKE256-v11"
	*/
)

// Available returns whether the selected ciphersuite is available.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ed25519, Ristretto255, P256, Secp256k1:
		return true
	case ed448:
		return false
	default:
		return false
	}
}

// Configuration returns a configuration created for the ciphersuite.
func (c Ciphersuite) Configuration() *Configuration {
	if !c.Available() {
		return nil
	}

	switch c {
	case Ed25519:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte(ed25519ContextString),
				Hash:          hash.SHA512,
				Group:         group.Edwards25519Sha512,
			},
		}
	case Ristretto255:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				Group:         group.Ristretto255Sha512,
				Hash:          hash.SHA512,
				ContextString: []byte(ristretto255ContextString),
			},
		}
	case P256:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				Group:         group.P256Sha256,
				Hash:          hash.SHA256,
				ContextString: []byte(p256ContextString),
			},
		}
	case Secp256k1:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte(secp256k1ContextString),
				Hash:          hash.SHA256,
				Group:         group.Secp256k1,
			},
		}
	case ed448:
		return nil
	default:
		return nil
	}
}

type ParticipantList []*Participant

func (p ParticipantList) Get(id *group.Scalar) *Participant {
	for _, i := range p {
		if i.ParticipantInfo.KeyShare.Identifier.Equal(id) == 1 {
			return i
		}
	}

	return nil
}

// Configuration holds long term configuration information.
type Configuration struct {
	GroupPublicKey *group.Element
	Ciphersuite    internal.Ciphersuite
}

// Participant returns a new participant of the protocol instantiated from the configuration an input.
func (c Configuration) Participant(id, keyShare *group.Scalar) *Participant {
	return &Participant{
		ParticipantInfo: ParticipantInfo{
			KeyShare: &secretsharing.KeyShare{
				Identifier: id,
				SecretKey:  keyShare,
			},
			Lambda: nil,
		},
		Nonce:         [2]*group.Scalar{},
		HidingRandom:  nil,
		BindingRandom: nil,
		Configuration: c,
	}
}

// Commitment is the tuple defining a commitment.
type Commitment []*group.Element

// DeriveGroupInfo returns the group public key as well those from all participants.
func DeriveGroupInfo(g group.Group, max int, coms secretsharing.Commitment) (*group.Element, Commitment) {
	pk := coms[0]
	keys := make(Commitment, max)

	for i := 0; i < max; i++ {
		id := internal.IntegerToScalar(g, i)
		pki := derivePublicPoint(g, coms, id)
		keys[i] = pki
	}

	return pk, keys
}

// TrustedDealerKeygen uses Shamir and Verifiable Secret Sharing to create secret shares of an input group secret.
// These shares should be distributed securely to relevant participants. Note that this is centralized and combines
// the shared secret at some point. To use a decentralized dealer-less key generation, use the dkg package.
func TrustedDealerKeygen(
	g group.Group,
	secret *group.Scalar,
	max, min int,
	coeffs ...*group.Scalar,
) ([]*secretsharing.KeyShare, *group.Element, secretsharing.Commitment, error) {
	ss, err := secretsharing.New(g, uint(min)-1, coeffs...)
	if err != nil {
		return nil, nil, nil, err
	}

	privateKeyShares, coeffs, err := ss.Shard(secret, uint(max))
	if err != nil {
		return nil, nil, nil, err
	}

	coms := secretsharing.Commit(g, coeffs)

	return privateKeyShares, coms[0], coms, nil
}

func derivePublicPoint(g group.Group, coms secretsharing.Commitment, i *group.Scalar) *group.Element {
	publicPoint := g.NewElement().Identity()
	one := g.NewScalar().One()

	j := g.NewScalar().Zero()
	for _, com := range coms {
		publicPoint.Add(com.Copy().Multiply(i.Copy().Pow(j)))
		j.Add(one)
	}

	return publicPoint
}

// Verify allows verification of a participant's secret share given a VSS commitment to the secret polynomial.
func Verify(g group.Group, share *secretsharing.KeyShare, coms secretsharing.Commitment) bool {
	pk := g.Base().Multiply(share.SecretKey)
	return secretsharing.Verify(g, share.Identifier, pk, coms)
}

func SaveSecretShares(configuration *Configuration, privateKeyShares []*secretsharing.KeyShare) {
	for i, sk_share := range privateKeyShares {
		f, _ := os.OpenFile("mykey"+strconv.Itoa(i), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		defer f.Close()
		sk_marshal, _ := sk_share.SecretKey.MarshalBinary()
		fmt.Printf(">>>>secret key %v\n", sk_marshal)
		new_key := configuration.Ciphersuite.Group.NewScalar()
		new_key.UnmarshalBinary(sk_marshal)
		sk_share.SecretKey.Set(new_key)
		id, _ := sk_share.Identifier.MarshalBinary()
		fmt.Printf(">>>>>>>id: %v\n", id)
		f.Write(id)
		f.Write(sk_marshal)
	}
}

func LoadSecretShare(keyname string, configuration *Configuration) *secretsharing.KeyShare {
	b, _ := os.ReadFile(keyname)
	new_key := configuration.Ciphersuite.Group.NewScalar()

	new_key.UnmarshalBinary(b[32:])
	new_id := configuration.Ciphersuite.Group.NewScalar()
	new_id.UnmarshalBinary(b[0:32])

	return &secretsharing.KeyShare{
		Identifier: new_id,
		SecretKey:  new_key,
	}

}

// GenerateSaveEd25519 generates and saves ed25519 keys to disk after
// encoding into PEM format
func GenerateSaveEd25519(keyName string, pub ed25519.PublicKey) error {

	var (
		err   error
		b     []byte
		block *pem.Block
	)

	if err != nil {
		fmt.Printf("Generation error : %s", err)
		os.Exit(1)
	}

	// public key
	b, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}

	block = &pem.Block{
		Type: "CERTIFICATE",
		// Type:  "PUBLIC KEY",
		Bytes: b,
	}

	fileName := keyName + ".pub"
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0644)
	return err

}

func ToEd25519(pk ed25519.PublicKey) (ed25519.PublicKey, error) {
	// public key
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type: "CERTIFICATE",
		// Type:  "PUBLIC KEY",
		Bytes: b,
	}

	parseResult, _ := x509.ParsePKIXPublicKey(block.Bytes)
	key := parseResult.(ed25519.PublicKey)

	return key, nil
}

func LoadPubKeyEd25519(name string) ed25519.PublicKey {
	var pemString, _ = os.ReadFile(name + ".pub")
	block, _ := pem.Decode(pemString)
	parseResult, _ := x509.ParsePKIXPublicKey(block.Bytes)
	key := parseResult.(ed25519.PublicKey)
	return key
}

func LoadPubKeyFrost(name string) *group.Element {
	pb, _ := os.ReadFile("mykey.o.pub")
	configuration := Ed25519.Configuration()
	groupPublicKey := configuration.Ciphersuite.Group.NewElement()
	groupPublicKey.UnmarshalBinary(pb)
	return groupPublicKey
}

func IdFromInt(g group.Group, i int) (*group.Scalar, error) {
	id := g.NewScalar()
	if err := id.SetInt(big.NewInt(int64(i))); err != nil {
		return nil, err
	}

	return id, nil
}

// dkgGenerateKeys generates sharded keys for maxSigner participant without a trusted dealer, and returns these shares
// and the group's public key.
func DkgGenerateKeys(
	conf *Configuration,
	maxSigners, threshold int,
) ([]*secretsharing.KeyShare, *group.Element, error) {
	g := conf.Ciphersuite.Group

	// Create participants.
	participants := make([]*dkg.Participant, maxSigners)
	for i := 0; i < maxSigners; i++ {
		id, err := IdFromInt(conf.Ciphersuite.Group, i+1)
		if err != nil {
			return nil, nil, err
		}
		participants[i] = dkg.NewParticipant(conf.Ciphersuite, id, maxSigners, threshold)
	}

	// Step 1 & 2.
	r1Data := make([]*dkg.Round1Data, maxSigners)
	for i, p := range participants {
		r1Data[i] = p.Init()
	}

	// Step 3 & 4.
	r2Data := make(map[string][]*dkg.Round2Data)
	for _, p := range participants {
		id := string(p.Identifier.Encode())
		r2Data[id] = make([]*dkg.Round2Data, 0, maxSigners-1)
	}

	for _, p := range participants {
		r2DataI, err := p.Continue(r1Data)
		if err != nil {
			return nil, nil, err
		}

		for _, r2d := range r2DataI {
			id := string(r2d.ReceiverIdentifier.Encode())
			r2Data[id] = append(r2Data[id], r2d)
		}
	}

	// Step 5.
	secretShares := make([]*secretsharing.KeyShare, maxSigners)
	groupPublicKey := g.NewElement()
	for i, p := range participants {
		id := string(p.Identifier.Encode())
		secret, _, pk, err := p.Finalize(r1Data, r2Data[id])
		if err != nil {
			return nil, nil, err
		}

		secretShares[i] = &secretsharing.KeyShare{
			Identifier: p.Identifier,
			SecretKey:  secret,
		}
		// sb := secret.Encode()
		groupPublicKey = pk
	}

	return secretShares, groupPublicKey, nil
}

func Sign(configuration *Configuration, privateKeyShares []*secretsharing.KeyShare, groupPublicKey *group.Element, message []byte) []byte {
	max := 3
	// threshold := 2
	participantListInt := []int{1, 2}

	configuration.GroupPublicKey = groupPublicKey
	g := configuration.Ciphersuite.Group

	// Create Participants
	participants := make(ParticipantList, max)
	for i, share := range privateKeyShares {
		participants[i] = &Participant{
			Configuration:   *configuration,
			ParticipantInfo: ParticipantInfo{KeyShare: share},
		}
	}

	signatureAggregator := &Participant{
		Configuration: *configuration,
	}

	// Round One: Commitment
	participantList := make([]*group.Scalar, len(participantListInt))
	for i, p := range participantListInt {
		participantList[i] = internal.IntegerToScalar(g, p)
	}

	comList := make(internal.CommitmentList, len(participantList))
	for i, id := range participantList {
		p := participants.Get(id)
		comList[i] = p.Commit()
	}

	comList.Sort()
	_, _ = comList.ComputeBindingFactors(configuration.Ciphersuite, message)

	// Round Two: Sign
	sigShares := make([]*group.Scalar, len(participantList))
	for i, id := range participantList {
		p := participants.Get(id)

		sigShare, err := p.Sign(message, comList)
		if err != nil {
			println("t.FATAL", err)
		}

		sigShares[i] = sigShare
	}

	// Final step: aggregate
	aggregateSig := signatureAggregator.Aggregate(comList, message, sigShares)

	return aggregateSig.Encode()

}

func FrostVerify(groupPublicKey []byte, message []byte, signature []byte) bool {
	res := ed25519.Verify(groupPublicKey, message, signature)
	return res
}

func FrostKeyGen(maxSigners, threshold int) ([]*secretsharing.KeyShare, *group.Element, error) {
	conf := Ed25519.Configuration()
	return DkgGenerateKeys(conf, maxSigners, threshold)
}

func FrostSign(conf *Configuration, privateKeyShares []*secretsharing.KeyShare, groupPublicKey *group.Element, message []byte) []byte {
	return Sign(conf, privateKeyShares, groupPublicKey, message)
}
