// 음성 대조: 같은 패키지를 import 하지만 취약 심볼은 부르지 않는다.
// 기대: 패키지 수준(imported)으로만 나오고 심볼 수준(called)은 0건.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	fmt.Println(language.Korean.String())
}
