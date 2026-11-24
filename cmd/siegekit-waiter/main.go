// Command siegekit-waiter is the first process of every tool container
// (ADR 0067). It is built as a static Linux program and embedded in
// SiegeKit; see internal/waiter and internal/waiterbin.
package main

import (
	"os"

	"github.com/Gobbuwu/SiegeKit/internal/waiter"
)

func main() {
	os.Exit(waiter.Main(os.Args[1:]))
}
