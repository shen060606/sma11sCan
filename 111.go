package main

import (
	"fmt"
	"sync"
)

func main() {
	sum := []int{1, 2, 3, 4, 5}

	wg := sync.WaitGroup{}

	for _, val := range sum {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(val)
		}()
	}

	wg.Wait()

}
