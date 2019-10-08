package SSHHost

import (
	"errors"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

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
	err := h.Connect()
	if err != nil {
		log.Println("Failed to connect to host ", h.hostAddress, "Error ", err)
		return nil, err
	}

	h.IsConnected = true
	return h, nil
}

func (h *SSHHost) Connect() error {
	if !h.IsConnected {
		var err error
		h.Client, err = ssh.Dial("tcp", h.hostAddress, h.Config)
		if err != nil {
			log.Println("SSH connection failed ", err)
			return err
		} else {

		}
	}
	// no need to connect if it's already connected
	return nil
}

func (h *SSHHost) RunCommand(commandline string) (*string, error) {
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

func (h *SSHHost) DownloadFile(remotePath string, localPath string) error {
	fileInfo, err := os.Stat(localPath)
	if err != nil {
		log.Println("Error: problem accessing ", localPath, " error: ", err)
		return err
	}

	if !fileInfo.IsDir() {
		log.Println("Error : ", localPath, " is not a directory")
		return errors.New("Error : " + localPath + " is not a directory")
	}

	session, err := h.Client.NewSession()
	if err != nil {
		log.Println("Error : Can't create new session to the host ", h.hostAddress)
		return err
	}

	err = scp.CopyPath(localPath, remotePath, session)
	return err
}

func (h *SSHHost) UploadFile(remotePath string, localPath string) error {
 return nil
}

func (h *SSHHost) DownloadDir(renotePath string, localPath string) error {
 return nil
}

func (h *SSHHost) UploadDir(hostPath string, localPath string) error {
 return nil
}

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
