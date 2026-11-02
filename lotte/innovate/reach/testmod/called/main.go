// 양성 대조: 취약 심볼 language.ParseAcceptLanguage를 직접 부른다.
// golang.org/x/text v0.3.6은 GO-2021-0113(수정 0.3.7), GO-2022-1059(수정 0.3.8) 범위에 든다.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tags, _, err := language.ParseAcceptLanguage("ko-KR,ko;q=0.9,en;q=0.8")
	fmt.Println(tags, err)
}
