/*
 This is a Remote Administration Tool
	AKA: RAT

	written in Golang

	As a practice in learning Golang

	And as a tutorial for "the Church Of The Subhacker" Wiki

	This tutorial assumes some familiarity with programming concepts, languages, and networking
*/

// make our module
package main

// import the libraries we need
import (
	"color"
	"bufio"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"io/ioutil"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// declaring global variables to share our network information between scopes
// these are for TCP specifically
var local_tcpaddr_LAN net.TCPAddr
var local_tcpaddr_WAN net.TCPAddr

//Admin Password in an obvious place
// TODO: set these for "hardmode" section
var sha256_admin_pass_preencrypted sha256 = "1cbec737f863e4922cee63cc2ebbfaafcd1cff8b790d8cfd2e6a5d550b648afa"
var sha512_admin_pass_preencrypted sha512;

// Horribly insecure implementation
var sha256_admin_pass_insecure sha256 = sha256.Sum256([]byte("admin"))

// struct to represent an OS command from the wire
// we will be shoving a JSON payload into this
type Command struct {
	Task_id int
	command_string  string
	info_message    string
	success_message string
	failure_message string
}
/* 
function to hash a string to compare against the hardcoded password
 never hardcode a password in plaintext
 we use the strongest we can and a good password...

 For the putposes of this tutorial, we use a weak password.
*/
func hash_auth_check(password string) {
	//Various Hashes, in order of increasing security
	// dont use this
	md5_password_hash := md5.Sum([]byte(password))
	// or this
	sha1_password_hash := sha1.Sum([]byte(password))
	// this is ok-ish, if you have a long password
	sha256_password_hash := sha256.Sum256([]byte(password))
}
// the obvious, a plaintext password, hardcoded
func insecure_password_check(password string){

}
// function to get the hash of a file for integrity checking
func file_hash(path string){
	// read the file from path
	file_input, error := ioutil.ReadFile(path)
	// create hash instance
	file_hash := sha256.New()
	// compute hash , if error, log error
	if _, err := io.Copy(file_hash, input); err != nil {
    	log.Fatal(err)
	}
	sum := hash.Sum(nil)
}
// function to provide outbound connections via threading
func tcp_outbound(laddr net.TCPAddr,
	raddr net.TCPAddr,
	port int8) {
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
