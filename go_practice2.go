/******************************************************************************
 This is a Remote Administration Tool, Command And Control Binary

    written in Golang

    As a practice in learning Golang

    And as a tutorial for "the Church Of The Subhacker" Wiki

    This tutorial assumes some familiarity with programming concepts,
	languages, and networking

	This is the other half of a two part tutorial
	on programming for hackers

=================================================================
/*/

// make our module
package go_practice

// import the libraries we need
import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"

	"github.com/fatih/color"
	/*/  IMPORTING MODULES YOU FIND ONLINE
		in the terminal in VSCODE, while in the package root directory,
		append the following imports, as is, to the command "go get"

		Example:

		go get github.com/hashicorp/mdns

		And it will install the modules to the
		GOMODCACHE environment variable

	/*/// for colorized printing
	// basic ANSI Escape sequences
	// necessary for multicast DNS
)

// declaring global variables to share our
// network information between scopes
// these are for TCP/UDP specifically
// instanced without a value assigned
var local_tcpaddr_LAN net.TCPAddr
var local_tcpaddr_WAN net.TCPAddr
var local_udpaddr_LAN net.UDPAddr
var local_udpaddr_WAN net.UDPAddr

// Command And Control
// At the top level scope (module level)
// you declare with a simple "="
// instanced with a value assigned
var remote_tcpport string = ":1337"
var remote_tcpaddr string = "192.168.0.2" + remote_tcpport
var remote_udpport string = ":1337"
var remote_udpaddr string = remote_tcpaddr + remote_udpport

// struct to represent an OS command from the wire
// we will be shoving a JSON payload into this
type Command struct {
	Task_id         int
	command_string  string
	info_message    string
	success_message string
	failure_message string
}

// Container for Outgoing messages to the Command And Control
type OutgoingMessage struct {
	contents string
}

// Colorized error printing to see what we are doing
func error_printer(error_object error, message string) {

	error_as_string := fmt.Errorf(error_object.Error())
	// I dont get it but whatever, gotta access Error twice?
	color.Red(error_as_string.Error(), message)
}

// This gets placed in a loop to handle net.Conn type
// containing json
// AFTER AUTH
func json_extract(
	pure_json bool,
	text string,
	command_struct Command) {
	/*/
		use Unmarshal if we expect our data to be pure JSON
		second parameter is the address of the struct
		we want to store our arsed data in
	/*/
	if pure_json == true {
		json.Unmarshal([]byte(text), &command_struct)
	}
	// read our opened jsonFile as a byte array.
	//byteValue, _ := ioutil.ReadAll()
	decoder, err := json.Decoder()
}

/*/
Function for packing up a string
/*/
func json_pack(json_string string, outgoing_message OutgoingMessage) {

	encoded_json, err := json.Marshal(json_string)
}

// function to provide basic interactive usage
func terminal_user_input() {

}

//function top authenticate with the RAT that has been activated on the
// target machine, We call these :
// "zombies", "bots", "hey dude, just type this into a python shell"

func auth_with_zombie() {

}

// function to provide outbound connections via threading
//-----------------Local IP---------Remote IP---------PORT-------
func tcp_outbound(laddr net.TCPAddr, raddr net.TCPAddr, port int8) {
	// the network functions return two objects
	// a connection
	// and an error
	connection, err := net.DialTCP("tcp", &laddr, &raddr)
	//generic error printing
	// if error isnt empty/null/nothingness
	if err != nil {
		// print the error
		error_printer(err, "[-] Error: TCP Connection Failed")
		return
	}
	// if there was no error, continue to the control loop
	// will be basis of control flow
	for {
		netData, error := bufio.NewReader(connection).ReadString('\n')
		// again with the error checking, what are we? Hackers?
		if error != nil {
			fmt.Println(error)
			return
		}
		// if we get a message from the victim
		json_extract()
	}
}

/*
control flow for network operation with tcp protocol
this function will contain the logic to spawn threads
of the following functions

*/
func tcp_network_io() {

	//generic error printing
	if err != nil {
		fmt.Println(err)
		return
	}

}
