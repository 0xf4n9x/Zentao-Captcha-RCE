// @File    :   main.go
// @Time    :   2023/01/17 14:25:22
// @Author  :   _0xf4n9x_
// @Version :   1.0
// @Contact :   fanq.xu@gmail.com

package main

import (
	"bufio"
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

const banner = `
####### #######  #####                                           ######   #####  ####### 
     #     #    #     #   ##   #####  #####  ####  #    #   ##   #     # #     # #       
    #      #    #        #  #  #    #   #   #    # #    #  #  #  #     # #       #       
   #       #    #       #    # #    #   #   #      ###### #    # ######  #       #####   
  #        #    #       ###### #####    #   #      #    # ###### #   #   #       #       
 #         #    #     # #    # #        #   #    # #    # #    # #    #  #     # #       
#######    #     #####  #    # #        #    ####  #    # #    # #     #  #####  #######
`

var (
	h        bool
	target   string
	proxyURL string
	command  string
	stdin    bool
)

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0
	return isPipedFromChrDev || isPipedFromFIFO
}

func init() {
	flag.BoolVar(&h, "h", false, "Show help.")
	flag.StringVar(&target, "t", "", "URL Target.")
	flag.StringVar(&proxyURL, "p", "", "Proxy URL.")
	flag.StringVar(&command, "c", "", "Input a command to remote command execution.")
	flag.Parse()

	stdin = hasStdin()

	showBanner()

	// -h flag or no flag, no stdin
	if h || (len(os.Args) == 1 && !stdin) {
		flag.Usage()
		os.Exit(0)
	}

	// no target and no stdin
	if target == "" && !stdin {
		gologger.Error().Msg("Target cannot be empty, use the -h flag to see the usage help.\n\n")
	}

	// stdin to target
	if stdin && target == "" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			t := scanner.Text()
			if t == "" {
				continue
			}
			target = t

			// fmt.Print(target)
		}
	}
	// fmt.Printf("Target: " + target + "\n")
	// fmt.Printf("command: " + command + "\n")
	// fmt.Printf("proxyURL: " + proxyURL + "\n")
}

func main() {

}

// func string checkURL() error {

// }
