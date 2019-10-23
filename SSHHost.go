package SSHHost

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SSHHost is the base struct for all SSH stuff
type SSHHost struct {
	hostAddress string
	Config      *ssh.ClientConfig
	Client      *ssh.Client
	IsConnected bool
}

func (h *SSHHost) createPublicKeys(keyfile string) (authmethod ssh.AuthMethod, err error) {

	_, err = os.Stat(keyfile)
	if err != nil {
		log.Println("Couldn't access keyfile specified ", keyfile)
		return nil, err
	}

	buffer, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(key), nil

}

// Init ... Initialize SSHHost
func (h *SSHHost) Init(ipAddress string, port int, username string, password string, keyfile string) (*SSHHost, error) {
	log.Println("Enter SSHHost Init")
	h.hostAddress = ipAddress + ":" + strconv.Itoa(port)
	h.IsConnected = false
	h.Config = new(ssh.ClientConfig)
	h.Config.SetDefaults()
	h.Config.User = username
	h.Config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	if len(password) > 0 {
		h.Config.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
	} else {
		keysMethod, err := h.createPublicKeys(keyfile)
		if err != nil {
			log.Println("Cannot continue since password is nil and keyfile has a problem ", err)
			return h, err
		}

		h.Config.Auth = []ssh.AuthMethod{
			keysMethod,
		}
	}

	log.Println("SSH Configuration complete. Initializing client")
	// Issue 1: SSHHost becomes nil if the connection fails.
	// we get a panic. Removing the connect code out of the
	// init.
	return h, nil
}

// SetCiphers ... For those cranky hosts which would not like defaults
func (h *SSHHost) SetCiphers(ciphers *[]string) error {
	if ciphers == nil {
		return errors.New("nil ciphers")
	}
	if len(*ciphers) == 0 {
		return errors.New("Ciphers can't be len 0 ")
	}
	h.Config.Ciphers = *ciphers
	h.Config.HostKeyAlgorithms = *ciphers
	return nil
}

// Connect to the Server called by Init and someone
func (h *SSHHost) Connect() error {
	if !h.IsConnected {
		var err error
		// Issue 1: Adding the connect here
		h.Client, err = ssh.Dial("tcp", h.hostAddress, h.Config)
		if err != nil {
			log.Println("SSH connection failed ", err)
			return err
		} else {
			h.IsConnected = true
		}
	}

	// no need to connect if it's already connected
	return nil
}

// RunCommand ... Run a command over SSH and get stdout as result
func (h *SSHHost) RunCommand(commandline string) (*string, error) {
	if h.Client == nil {
		return nil, errors.New("Client is not initialized")
	}
	session, err := h.Client.NewSession()
	if err != nil {
		log.Println("Error : Can't create new session to the host ", h.hostAddress)
		return nil, err
	}

	output, err := session.Output(commandline)
	if err != nil {
		return nil, err
	}
	session.Close()
	outputString := string(output)
	return &outputString, nil

}

// DownloadFile ...
func (h *SSHHost) DownloadFile(remotePath string, localPath string) error {

	client, err := sftp.NewClient(h.Client)
	if err != nil {
		log.Println("DownloadFile : Failed to create sftp client", err)
		return err
	}
	defer client.Close()
	remoteStat, err := client.Stat(remotePath)
	if err != nil {
		log.Println("DownloadFile : Remote Stat Failed")
	}
	if remoteStat.Mode().IsDir() {
		return errors.New("DownloadFile : " + remotePath + " is a directory")
	}

	localFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Println("DownloadFile: Couldn't Open local file ", err)
	}

	bytes, err := client.ReadTo(localFile)
	if err != nil || bytes != remoteStat.Size() {
		log.Println("DownloadFile : failed to copy file completely. remote file size ", bytes)
		os.Remove(localPath)
		return err
	}

	return nil

}

// UploadFile ...
func (h *SSHHost) UploadFile(remotePath string, localPath string) error {
	return errors.New("Not Implemented")
}

// DownloadDir ...
func (h *SSHHost) DownloadDir(renotePath string, localPath string) error {
	return errors.New("Not Implemented")
}

// UploadDir ...
func (h *SSHHost) UploadDir(hostPath string, localPath string) error {
	return errors.New("Not Implemented")
}

// Close ...
func (h *SSHHost) Close() {
	if h.IsConnected {
		h.Client.Close()
	}
}

// private calls

// TODO: Check how to monitor the channel and add reconnect as a error or callback handler
func (h *SSHHost) reconnect() error {
	return h.Connect()
}
