// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run root_darwin_arm_gen.go -output root_darwin_armx.go

package x509

import (
	"bytes"
	"crypto/sha1"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	debugExecDarwinRoots = strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")

	// From Apple Security OSS trust/SecTrustSettings.h
	kSecTrustSettingsResultDeny = "3"
)

func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	return nil, nil
}

// This code is only used when compiling without cgo.
// It is here, instead of root_nocgo_darwin.go, so that tests can check it
// even if the tests are run with cgo enabled.
// The linker will not include these unused functions in binaries built with cgo enabled.

// execSecurityRoots finds the macOS list of trusted root certificates
// using only command-line tools. This is our fallback path when cgo isn't available.
//
// The strategy is as follows:
//
// 1. Run "security trust-settings-export" and "security
//    trust-settings-export -d" to discover the set of certs with some
//    user-tweaked trust policy. Parse that resulting xml and understand
//    what the trust policies actually are.
//
// 2. Run "security find-certificate" to dump the list of system root
//    CAs in PEM format.
//
// 3. For each dumped cert, check if the certificate is marked as 'trustRoot'
//    and if so add to our CertPool
func execSecurityRoots() (*CertPool, error) {
	certPolicies, err := getCertsWithTrustPolicy()
	if err != nil {
		return nil, err
	}
	if debugExecDarwinRoots {
		println(fmt.Sprintf("crypto/x509: %d certs have a trust policy", len(certPolicies)))
	}

	args := []string{"find-certificate", "-a", "-p",
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	u, err := user.Current()
	if err != nil {
		if debugExecDarwinRoots {
			println(fmt.Sprintf("crypto/x509: get current user: %v", err))
		}
	} else {
		args = append(args,
			filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain"),

			// Fresh installs of Sierra use a slightly different path for the login keychain
			filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain-db"),
		)
	}

	cmd := exec.Command("/usr/bin/security", args...)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	roots := NewCertPool()

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sha1CapHex := fmt.Sprintf("%X", sha1.Sum(block.Bytes))

		policies, exists := certPolicies[sha1CapHex]
		if !exists { // no user defined policy so accept the cert
			roots.AddCert(cert)
			continue
		}
		trusted := true
		for i := range policies {
			if policies[i].name == "sslServer" && policies[i].result == kSecTrustSettingsResultDeny {
				trusted = false
				if debugExecDarwinRoots {
					println(fmt.Sprintf("crypto/x509: %s has Deny policy set", cert.Subject))
				}
				break
			}
		}
		if trusted {
			roots.AddCert(cert)
		}
	}

	return roots, nil
}

type trustPolicy struct {
	name string // kSecTrustSettingsPolicyName values (e.g. basicX509, sslServer, CodeSigning)
	result string // kSecTrustSettingsResult
}

// getCertsWithTrustPolicy returns the set of certs that have a
// possibly-altered trust policy.
//
// The keys of the map are capitalized sha1 hex of the raw cert.
// The values of the map are arrays of trustPolicy which hold the
// policy name and result
//
// This code is only used for cgo-disabled builds.
func getCertsWithTrustPolicy() (map[string][]*trustPolicy, error) {
	set := map[string][]*trustPolicy{}

	td, err := ioutil.TempDir("", "x509trustpolicy")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)
	run := func(file string, args ...string) error {
		file = filepath.Join(td, file)
		args = append(args, file)
		cmd := exec.Command("/usr/bin/security", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// If there are no trust settings, the
			// `security trust-settings-export` command
			// fails with:
			//    exit status 1, SecTrustSettingsCreateExternalRepresentation: No Trust Settings were found.
			// Rather than match on English substrings that are probably
			// localized on macOS, just interpret any failure to mean that
			// there are no trust settings.
			if debugExecDarwinRoots {
				println(fmt.Sprintf("crypto/x509: exec %q: %v, %s", cmd.Args, err, stderr.Bytes()))
			}
			return nil
		}

		bs, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}

		plist := plist{}
		err = xml.Unmarshal(bs, &plist)
		if err != nil {
			return err
		}

		for i := range plist.Dict {
			// Grab all SHA1 hashesn
			// <key>02FAF3E291435468607857694DF5E45B68851868</key>
			// <dict>
			//   ...
			// </dict>
			hashes := plist.Dict[i].Dict[0].Key

			// Dive down into the xml
			for j := range plist.Dict[i].Dict {
				for k := range plist.Dict[i].Dict[j].Dict {
					dict := plist.Dict[i].Dict[j].Dict[k]

					hash := hashes[k].Text
					for l := range dict.Key {
						if dict.Key[l].Text == "trustSettings" {
							set[hash] = parseTrustSettings(dict)
							println(fmt.Sprintf("found trustSettings for %s, %v", hash[:8], set[hash]))
						}
					}
				}
			}
		}
		return nil
	}

	if err := run("user", "trust-settings-export"); err != nil {
		return nil, fmt.Errorf("dump-trust-settings (user): %v", err)
	}
	if err := run("admin", "trust-settings-export", "-d"); err != nil {
		return nil, fmt.Errorf("dump-trust-settings (admin): %v", err)
	}
	return set, nil
}

var (
	nonContentRegex    = regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
	whitespaceReplacer = strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")
)

type plist struct {
	Dict []*Dict `xml:"dict,omitempty"`
}

type Dict struct {
	Array *Array `xml:"array,omitempty"`
	Dict []*Dict `xml:"dict,omitempty"`
	Integer []*Integer `xml:"integer,omitempty"`
	Key []*Key `xml:"key,omitempty"`
	String *String `xml:"string,omitempty"`
}

type Key struct {
	Text string `xml:",chardata"`
}

type Array struct {
	Dict []*Dict `xml:"dict,omitempty"`
}

type Integer struct {
	Text string `xml:",chardata"`
}

type String struct {
	Text string `xml:",chardata"`
}

// <key>trustSettings</key>
// <array>
//     <dict>
// 	<key>kSecTrustSettingsResult</key>
// 	<integer>4</integer>
//     </dict>
// </array>
func parseTrustSettings(dict *Dict) []*trustPolicy {
	var policies []*trustPolicy

	for l := range dict.Array.Dict {
		policy := trustPolicy{}
		for m := range dict.Array.Dict[l].Key {
			key := strings.TrimSpace(dict.Array.Dict[l].Key[m].Text)
			switch key {
			case "kSecTrustSettingsResult":
				if len(dict.Array.Dict) >= l+1 {
					policy.result = strings.TrimSpace(dict.Array.Dict[l].Integer[0].Text)
				}

			case "kSecTrustSettingsPolicyName":
				if len(dict.Array.Dict) >= l+1 {
					policy.name = strings.TrimSpace(dict.Array.Dict[l].String.Text)
				}
			}
		}
		if policy.name != "" && policy.result != "" {
			policies = append(policies, &policy)
		} else if debugExecDarwinRoots {
			println(fmt.Sprintf("crypto/x509: not adding partially parsed policy %#v", policy))
		}
	}
	return policies
}
