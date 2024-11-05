package certmanager

import (
    "encoding/pem"
    "os"
)

func SavePEMFile(filename string, pemType string, bytes []byte) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    block := &pem.Block{
        Type:  pemType,
        Bytes: bytes,
    }

    return pem.Encode(file, block)
}
