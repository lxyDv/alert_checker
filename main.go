package main

import (
	"fmt"

	"github.com/spf13/viper"
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

func parseConfig() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	//viper.AddConfigPath("/etc/appname/")  // path to look for the config file in
	//viper.AddConfigPath("$HOME/.appname") // call multiple times to add many search paths
	viper.AddConfigPath(".")    // optionally look for config in the working directory
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	old_log := viper.GetString("old_log_path")
	new_log := viper.GetString("new_log_path")

	alert_regexp := viper.GetString("alert_regexp")
	file_regexp := viper.GetString("file_regexp")

	fmt.Println(alert_regexp)
	fmt.Println(file_regexp)

	fmt.Println(old_log)
	fmt.Println(new_log)

	//return config

}

func main() {

	a := alert{file: "44487149_84272ed585db9b05ec46a6691297b49a", timestamp: "07/21/2021-20:11:41.543776", sid: 44487149, msg: "Trojan.Agent.HTTP.C&C"}
	fmt.Println(a)

	parseConfig()

}

//use viper for yaml format
//structrure with lenght for table
//export to csv or db
//add rule content - interactivity

//--------------------------------------------------------------CSV PART
// package main

// import (
//     "encoding/csv"
//     "fmt"
//     "os"
// )

// func main() {
//     f, e := os.Create("./People.csv")
//     if e != nil {
//         fmt.Println(e)
//     }

//     writer := csv.NewWriter(f)
//     var data = [][]string{
//         {"Name", "Age", "Occupation"},
//         {"Sally", "22", "Nurse"},
//         {"Joe", "43", "Sportsman"},
//         {"Louis", "39", "Author"},
//     }

//     e = writer.WriteAll(data)
//     if e != nil {
//         fmt.Println(e)
//     }
// }
//--------------------------------------------------------------CSV PART
