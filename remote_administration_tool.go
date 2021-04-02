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
			touch ~/Desktop/go_practice/src/go_practice

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

	THINGS SHOULD WORK DO USE THE SUSPEND/SAVE STATE FUNCTION
	YOU WILL BREAK THE INSTALL (at least I did)

	... Careful changing the formatter to "gofmt" it hung my VM
*/

// make our module
package go_practice

// import the libraries we need
import (
	"bufio"
	"crypto"
	"fmt"

	"github.com/fatih/color"

	//"image/color"
	"io"
	"log"
	"net"
	"os"
	"strings"
	//@v1.10.0"
)

// declaring global variables to share our
// network information between scopes
// these are for TCP specifically
var local_tcpaddr_LAN net.TCPAddr
var local_tcpaddr_WAN net.TCPAddr

//-----NAME-------------TYPE-----

// Admin Password in an obvious place
// TODO: set these for "hardmode" section
var sha256_admin_pass_preencrypted crypto.Hash
var sha512_admin_pass_preencrypted crypto.Hash

// Horribly insecure implementation
var sha256_admin_pass_insecure crypto.Hash

//sha256_admin_pass_insecure.Sum256([]byte("admin"))

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
	color.Red(error_object, message)
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
	file_input, error := os.Open(path)
	if error != nil {
		// print the error
		fmt.Println(error)
		return
	}
	//close file when done reading
	defer file.Close()

	/*/
	     copy file buffer to hash compute buffer
		 the underscore character "_" is called a "blank identifier"
		 it allows you to ignore left side values
		 in this case, we are acting like the regular return value doesnt exist
		 and if there is an error, log that error and exit
		 otherwise, finish copying from buffer to buffer
	    /*/
	if _, error := io.Copy(file_hash, file_input); error != nil {
		log.Fatal(error)
	}
	// and compute the hash of the file you provided to this function
	file_hash_sha256 := file_hash.Sum(nil)
}

// function to provide outbound connections via threading
//-----------------Local IP---------Remote IP---------PORT-------
func tcp_outbound(laddr net.TCPAddr, raddr net.TCPAddr, port int8) {
	// the network functions return two objects
	// a connection
	// and an error
	connection, error := net.DialTCP("tcp", &laddr, &raddr)
	//generic error printing
	// if error isnt empty/null/nothingness
	if error != nil {
		// print the error
		fmt.Println(error)
		return
	}

	// if there was no error, continue to the control loop
	// will be basis of control flow
	for {
		netData, error := bufio.NewReader(connection).ReadString('\n')

		if error != nil {
			fmt.Println(error)
			return
		}
		// stops server if "STOP" Command is sent
		// TODO: JSONIFY THIS
		if strings.TrimSpace(string(netData)) == "STOP" {
			fmt.Println("Exiting TCP server!")
			return
		}
		connection.Write([]byte(myTime))
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
