/******************************************************************************
 This is a Remote Administration Tool
    AKA: RAT

    written in Golang

    As a practice in learning Golang

    And as a tutorial for "the Church Of The Subhacker" Wiki

    This tutorial assumes some familiarity with programming concepts, languages,
	 and networking
=================================================================
	KNOWN GOOD DEBIAN VM CONFIGURATION:
		Project Folder Structure
			mkdir ~/Desktop/go_practice
			mkdir ~/Desktop/go_practice/src/
			touch ~/Desktop/go_practice/src/go_practice.go

		Install the recomended go extension in VSCode
			- ctrl+shift+p - type in "Go : install tools"
			- select all the check boxes

		~/.bashrc:
			export GOPATH=/home/user/Desktop/go_practice
			export GOROOT=/home/user/go
			export GOMODCACHE=/home/user/Desktop/go_practice/src
			export PATH=$GOROOT:$GOPATH/bin:$PATH:/home/user/.local/bin:/home/user/go/bin

		settings.json in VSCODE:

	{
    	"window.zoomLevel": 2,
    	"workbench.editorAssociations": [
        	{
            	"viewType": "jupyter.notebook.ipynb",
            	"filenamePattern": "*.ipynb"
        	}
    	],
    	"go.goroot": "/home/moop/go",
    	"go.installDependenciesWhenBuilding": true,
    	"go.buildOnSave": "workspace",
    	"go.formatTool": "gofmt",
    	"go.languageServerFlags": [
        	"-rpc.trace"
      	]
	}

	Open the terminal in VSCode and type in
		- go mod init go_practice

	THINGS SHOULD WORK DO NOT USE THE SUSPEND/SAVE STATE FUNCTION
	YOU WILL BREAK THE INSTALL (at least I did)

	... Careful changing the formatter to "gofmt" it hung my VM
*/

// make our module
package go_practice

// import the libraries we need
import (
	"bufio"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	// for colorized printing
	// basic ANSI Escape sequences
	"github.com/fatih/color"

	// necessary for multicast DNS
	"github.com/hashicorp/mdns"
)

// declaring global variables to share our
// network information between scopes
// these are for TCP/UDP specifically
var local_tcpaddr_LAN net.TCPAddr
var local_tcpaddr_WAN net.TCPAddr
var local_udpaddr_LAN net.UDPAddr
var local_udpaddr_WAN net.UDPAddr

// Command And Control
var remote_tcpport string = ":1337"
var remote_tcpaddr string = "192.168.0.2" + remote_tcpport
var remote_udpport string = ":1337"
var remote_udpaddr string = remote_tcpaddr + remote_udpport
var PHONEHOME_TCP net.TCPAddr
var PHONEHOME_UDP net.UDPAddr
var mdns_server mdns.Server

//-----NAME-------------TYPE-----

// Admin Password in an obvious place
// TODO: set these for "hardmode" section
var sha256_admin_pass_preencrypted crypto.Hash
var sha512_admin_pass_preencrypted crypto.Hash

// Horribly insecure implementation
var sha256_hash_admin crypto.Hash
var new_admin_hash = sha256_hash_admin.New()
var wat = new_admin_hash.Sum([]byte("admin"))

// struct to represent an OS command from the wire
// we will be shoving a JSON payload into this
type Command struct {
	Task_id         int
	command_string  string
	info_message    string
	success_message string
	failure_message string
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
	text_from_conn string,
	command_struct Command) {
	/*/
		use Unmarshal if we expect our data to be pure JSON
		second parameter is the address of the struct
		we want to store our arsed data in
	/*/
	if pure_json == true {
		json.Unmarshal([]byte(text_from_conn), &command_struct)
	}
	decoder, err = json.Decoder(text_from_conn)
}

// Beacon
// makes requests outside the network to get to the C&C
// ONLY used for reaching out
func Bacon() {
	PHONEHOME_TCP.IP = net.IP(remote_tcpaddr)
	net.DialTCP(PHONEHOME_TCP)
}

/*
function to hash a string to compare against the hardcoded password
 never hardcode a password in plaintext
 we use the strongest we can and a good password...

 For the porpoises of this tutorial, we use a weak password.
*/

func hash_auth_check(password string) {
	//Various Hashes, in order of increasing security
	// dont use this
	md5_password_hash := crypto.MD5.New()
	md5_password_hash.Sum([]byte(password))
	// or this
	sha1_password_hash := crypto.MD5SHA1.New()
	sha1_password_hash.Sum([]byte(password))
	// this is ok-ish, if you have a long password
	sha256_password_hash := crypto.SHA512_256.New()
	sha256_password_hash.Sum([]byte(password))
}

// the obvious, a plaintext password, hardcoded
func insecure_password_check(password string) {

}

/*/
function to get the hash of a file for integrity checking
	create hash instance
		- this is a memory address we are going to shove a file into
	read the file from path
		- handle error if necessary
		- generic error printing
/*/
func file_hash(path string) {
	file_hash := crypto.SHA256.New()
	file_input, err := os.Open(path)
	if err != nil {
		// print the error
		fmt.Println(err)
		return
	}
	//close file when done reading
	defer file_input.Close()

	/*/
	     copy file buffer to hash compute buffer
		 the underscore character "_" is called a "blank identifier"
		 it allows you to ignore left side values
		 in this case, we are acting like the regular return value
		 doesnt exist and if there is an error, log that error and exit
		 otherwise, finish copying from buffer to buffer
	    /*/
	if _, error := io.Copy(file_hash, file_input); error != nil {
		log.Fatal(error)
	}
	// and compute the hash of the file you provided to this function
	//file_hash_sha256 := file_hash.Sum(nil)
	return file_hash.Sum(nil)

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
		json_extract()
		// stops server if "STOP" Command is sent
		// TODO: JSONIFY THIS
		if strings.TrimSpace(string(netData)) == "STOP" {
			fmt.Println("Exiting TCP server!")
			return
		}
		//sending wat!?!?
		//connection.Write("asdf")
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
