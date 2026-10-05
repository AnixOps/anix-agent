package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ANSI 颜色代码
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

var (
	version  = "v4.2.0-rc.2" // release builds replace this through ldflags
	codename = productName
	intro    = "AnixOps multi-core node agent"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

// rainbowText 将文本渲染成彩虹色
func rainbowText(text string) string {
	colors := []string{colorRed, colorYellow, colorGreen, colorCyan, colorBlue, colorPurple}
	result := ""
	colorIndex := 0
	for _, char := range text {
		if char == ' ' {
			result += string(char)
		} else {
			result += colors[colorIndex%len(colors)] + string(char)
			colorIndex++
		}
	}
	result += colorReset
	return result
}

func showVersion() {
	fmt.Println(rainbowText(productName))
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
	//fmt.Printf("Supported cores: %s\n", strings.Join(vCore.RegisteredCore(), ", "))
	// Warning
	//fmt.Println(Warn("This version need V2board version >= 1.7.0."))
	//fmt.Println(Warn("The version have many changed for config, please check your config file"))
}
