package client

import "testing"

func TestCreateClient(t *testing.T) {
	client := createClient()
	if client == nil{
		t.Errorf("empty client")
	}
}

func BenchmarkCreateClient(b *testing.B) {
	createClient()
}
