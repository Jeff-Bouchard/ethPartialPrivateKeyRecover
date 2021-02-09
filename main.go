package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"math"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

var (
	privateKey2   = "0000000000000000000000000000000000000000000000000000000123"
	publicAddress = "0x2eC6f3755fEbeCf2ABb36149eDFbfe7A089De3c5"
	maxChannels   = 8
)

func padZeroes(desiredLength int, str string) string {
	for len(str) < desiredLength {
		str = fmt.Sprintf("0%s", str)
	}
	return str
}

func calcPubKey(appended string) string {
	privateKey, err := crypto.HexToECDSA(privateKey2 + appended)
	if err != nil {
		log.Fatalf("err here for privKey(%s, LEN: %d): %v", privateKey2+appended, len(privateKey2+appended), err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	return fromAddress.Hex()
}

func main() {
	lengthToFill := 64 - len(privateKey2)
	start := time.Now()
	log.Printf("Finding private key for address %s\n", publicAddress)
	totalToCount := math.Pow(16, float64(lengthToFill))
	log.Printf("Number of characters needed to complete private key: %d\n", lengthToFill)
	log.Printf("Maximum number of private keys to check: %d\n", int(totalToCount))
	var wg sync.WaitGroup
	wg.Add(maxChannels)
	totalCount := 0

	totalToCountInt := int(totalToCount)
	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {

			select {
			case <-ticker.C:
				duration := time.Since(start)
				rate := float64(totalCount) / (duration.Seconds())
				log.Printf("Checked %d private keys in %dsec\tRate: %f keys/sec\tMaximum ETA: ~%dsec", totalCount, int(duration.Seconds()), rate, int64(float64(totalToCountInt-totalCount)/rate))
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	ch := make(chan string, 1)
	amtPerChan := totalToCountInt / maxChannels
	log.Printf("Starting %d parallel channels", maxChannels)
	for idx := 0; idx < maxChannels; idx++ {
		minSlice := idx * amtPerChan
		maxSlice := (idx + 1) * amtPerChan
		go func(minSlice int, maxSlice int) {
			for i := minSlice; i+1 < maxSlice; i++ {
				if len(ch) == cap(ch) {
					wg.Done()
					break
				}
				appended := padZeroes(lengthToFill, fmt.Sprintf("%x", i))
				pub := calcPubKey(appended)
				if strings.EqualFold(pub, publicAddress) {
					log.Println("Correct private key found for specified address: ", privateKey2+appended)
					ch <- privateKey2 + appended
					close(ch)
				}
				totalCount++
			}
			return
		}(minSlice, maxSlice)
	}
	wg.Wait()

	duration := time.Since(start)
	if int(duration.Milliseconds()) != 0 {
		log.Println("Checked", totalCount, "privateKeys in", duration.Milliseconds(), "ms;", float64(totalCount)/(duration.Seconds()), "keys/sec")
		outputPrivateKey := <-ch
		log.Printf("Found private key for public address \"%s\": \"%s\"\n", publicAddress, outputPrivateKey)
	}
}
