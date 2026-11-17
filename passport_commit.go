package main

import (
	"time"

	"go.etcd.io/bbolt"
)

// Callers hold mu across preparation, persistence, and publication so a newer
// cached identity cannot be replaced by an older committed copy.
func (p *PassportStore) commitLocked(principal *Principal, clients map[string]*ClientCredential, write func(*bbolt.Tx) error) error {
	err := p.db.Update(func(tx *bbolt.Tx) error {
		if write != nil {
			if err := write(tx); err != nil {
				return err
			}
		}
		if principal != nil {
			if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principal.ID, principal); err != nil {
				return err
			}
		}
		for id, client := range clients {
			if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), id, client); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if principal != nil {
		p.principals[principal.ID] = principal
	}
	for id, client := range clients {
		p.clients[id] = client
	}
	return nil
}

func (p *PassportStore) cutoffClientsLocked(principal *Principal) (map[string]*ClientCredential, error) {
	cutoff := nextCredentialCutoff(time.Now())
	principal.CredentialsValidAfter = cutoff
	clients := make(map[string]*ClientCredential)
	for id, existing := range p.clients {
		if existing.PrincipalID != principal.ID || existing.Status != "active" {
			continue
		}
		client := *existing
		client.ValidAfter = cutoff
		if err := p.rotateClientSecret(&client); err != nil {
			return nil, err
		}
		clients[id] = &client
	}
	return clients, nil
}
