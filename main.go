package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"

	"github.com/spf13/viper"
)

const (
	//Colors
	ColorRed    string = "\u001b[31m"
	ColorGreen         = "\u001b[32m"
	ColorBlack         = "\u001b[30m"
	ColorYellow        = "\u001b[33m"
	ColorBlue          = "\u001b[34m"
	ColorReset         = "\u001b[0m"
)

type alert struct {
	file      string
	timestamp string
	sid       int
	msg       string
}

type config struct {
	alert_pattern    string
	filename_pattern string
	old_log          string
	new_log          string
}

func main() {
	clear_terminal()

	a := alert{file: "44487149_84272ed585db9b05ec46a6691297b49a", timestamp: "07/21/2021-20:11:41.543776", sid: 44487149, msg: "Trojan.Agent.HTTP.C&C"}
	log.Println(a)

	conf := parseConfig()
	log.Println(conf)

	export_csv(a)

}

func parseConfig() config {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	//viper.AddConfigPath("/etc/appname/")  // path to look for the config file in
	//viper.AddConfigPath("$HOME/.appname") // call multiple times to add many search paths
	viper.AddConfigPath(".")    // optionally look for config in the working directory
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	conf := config{alert_pattern: viper.GetString("alert_regexp"), filename_pattern: viper.GetString("file_regexp"), old_log: viper.GetString("old_log_path"), new_log: viper.GetString("new_log_path")}
	return conf
}

func clear_terminal() {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "linux":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()

	}
}

func colorize(color string, message string) {
	fmt.Println(string(color), message, string(ColorReset))
}

func open_file(filePath string) []string {

	//read file
	readFile, err := os.Open(filePath)

	// check errors
	if err != nil {
		fmt.Println(err)
	}

	// scan lines from file
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	// save
	var fileLines []string

	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}
	readFile.Close()
	return fileLines
}

func parse_log_slice(log_content []string, r *regexp.Regexp, h *regexp.Regexp) []string {

	var alerts_list []string
	var filename string

	for _, v := range log_content {

		hash := h.FindStringSubmatch(v)
		if len(hash) > 0 {
			filename = hash[1]
		}

		match := r.FindAllStringSubmatch(v, -1)

		if len(match) > 0 {
			al := filename + " " + match[0][2] + " " + match[0][1] + " " + match[0][3]
			//fmt.Printf("%q", al)
			alerts_list = append(alerts_list, al)

		}
	}
	return alerts_list
}

// func rule_normalize (rulePath, sid string) string{
func rule_normalize_test(rulePath string) {

	re := regexp.MustCompile(`(?m)\\$\s`)
	substitution := ""

	//read file
	readFile, err := os.Open(rulePath)

	// check errors
	if err != nil {
		fmt.Println(err)
	}

	// scan lines from file
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	// save
	var ruleLines []string

	for fileScanner.Scan() {
		ruleLines = append(ruleLines, fileScanner.Text())
	}
	readFile.Close()

	for _, line := range ruleLines {
		fmt.Println(re.ReplaceAllString(line, substitution))

	}
}

// do for []alert and pass rule content by sid
func export_csv(a alert) {
	f, e := os.Create("./alerts.csv")
	if e != nil {
		fmt.Println(e)
	}

	writer := csv.NewWriter(f)
	var data = [][]string{
		{"File", "Sid", "Timestamp", "Rule"},
		{a.file, strconv.Itoa(a.sid), a.timestamp, a.msg},
		{a.file, strconv.Itoa(a.sid), a.timestamp, a.msg},
	}

	e = writer.WriteAll(data)
	if e != nil {
		fmt.Println(e)
	}
}

//func export_db () {}
//func draw_table (length width) {}
