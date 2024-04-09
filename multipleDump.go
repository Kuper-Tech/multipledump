package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Try to realize this behavior
// ssh -p 8022 root@${h} -i ~/.ssh/eve -C 'tcpdump -U -i '${i}' -w -' | /Applications/Wireshark.app/Contents/MacOS/Wireshark -i - -k 2>/dev/null &
const (
	//example Command := "ssh -i $HOME/.ssh/id_rsa.sbm nkulikov@127.0.0.6 -p 21057 -C \"sudo timeout 60 tcpdump -U -i any not tcp port ssh and host 10.3.1.1 -w -\""
	Command = "ssh -o StrictHostKeyChecking=no %s %s %s -C \"sudo timeout %s tcpdump -U -i %s %s -w -\""
)

var (
	Mu sync.Mutex

	SHBCode              = []byte{0x0a, 0x0d, 0x0d, 0x0a}
	SHBBytesOrderReverse = []byte{0x4d, 0x3c, 0x2b, 0x1a}
	SHBPersist           = false
	IDBCount             = byte(0)
	WriteChan            chan []byte
	WiresharkStarted     chan bool
	Hosts                FileConfig
	Cmds                 = make(map[int]*exec.Cmd)
	cmdEditCap           = make(map[int]*exec.Cmd)
	PacketsChans         = make(map[int]chan []byte)
)

type FileConfig struct {
	MacOSWireshark   string        `json:"MacOSWireshark"`
	WindowsWireshark string        `json:"WindowsWireshark"`
	PcapHead         string        `json:"PcapHead"`
	Hosts            []HostsStruct `json:"hosts"`
}
type HostsStruct struct {
	UserHost   string `json:"UserHost"`
	HostPort   string `json:"HostPort"`
	Key        string `json:"Key"`
	Interface  string `json:"Interface"`
	PcapFilter string `json:"PcapFilter"`
	Timeout    string `json:"Timeout"`
}

func ReadfromBufferOutChan(R io.ReadCloser, PacketsChan chan []byte) {
	for {
		buf := make([]byte, 65536)
		n, err := R.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Println(err.Error() + " dump ended")
				break
			} else {
				log.Fatalf("Error read buffer from ssh: %s", err.Error())
			}
		}

		if n > 0 {
			d := buf[:n]
			PacketsChan <- d
		}
	}
}

func BytestoIntReverse(bytes []byte) int {
	result := 0
	for i := len(bytes) - 1; i > -1; i-- {
		result = result << 8
		result += int(bytes[i])

	}
	return result
}
func BytestoIntForward(bytes []byte) int {
	result := 0
	for i := 0; i < len(bytes); i++ {
		result = result << 8
		result += int(bytes[i])

	}

	return result
}

func AnalizeSHB(b []byte) (YES bool, Lenght int, SHBHeader []byte, IDBHeader []byte, Reverse bool) {
	var (
		SHBLenght int
		R         bool
	)

	Cmp1 := bytes.Compare(b[:4], SHBCode)
	if Cmp1 == 0 {

		CmpR := bytes.Compare(b[8:12], SHBBytesOrderReverse) // Check Bytes Order
		if CmpR == 0 {
			R = true
			SHBLenght = BytestoIntReverse(b[4:8])
		} else {
			R = false
			SHBLenght = BytestoIntForward(b[4:8])
		}
		return true, SHBLenght, b[:SHBLenght], b[SHBLenght:], R
	}
	return false, 0, nil, nil, false
}

func EditEPB(Buf *[]byte, Reverse bool, IDBID byte) {
	var EditedBytes int
	B := *Buf
	if Reverse {
		copy(B[8:], []byte{IDBID})
		EditedBytes = BytestoIntReverse(B[4:8])
	} else {
		copy(B[11:], []byte{IDBID})
		EditedBytes = BytestoIntForward(B[4:8])
	}
	LenEPB := len(B)

	for EditedBytes < LenEPB {
		var NextEditedBytes int
		if Reverse {
			copy(B[EditedBytes+8:], []byte{IDBID})
			NextEditedBytes = BytestoIntReverse(B[EditedBytes+4 : EditedBytes+8])
		} else {
			copy(B[EditedBytes+11:], []byte{IDBID})
			NextEditedBytes = BytestoIntForward(B[EditedBytes+4 : EditedBytes+8])
		}
		EditedBytes = EditedBytes + NextEditedBytes
	}

}

func RewriteIDB(IDB []byte, HostName, Interface string, Reverse bool) []byte {
	// fmt.Println("--------------IDB Block---------------")
	OptCodeInterface := make([]byte, 2)
	// dt := time.Now()
	// os.WriteFile(dt.String()+".IDB.dump", IDB, 0644)

	IDBType := IDB[:4]
	LinkType := IDB[8:10]
	Reserved := IDB[10:12]
	SnapLen := IDB[12:16]
	OptCode := IDB[16:18]
	OptCodeLenght := IDB[18:20]
	var OptCodeLenghtInt int

	switch Reverse {
	case true:
		OptCodeInterface = []byte{02, 00}
		OptCodeLenghtInt = BytestoIntReverse(OptCodeLenght)
	case false:
		OptCodeInterface = []byte{00, 02}
		OptCodeLenghtInt = BytestoIntForward(OptCodeLenght)
	}
	Cmp := bytes.Compare(OptCode, OptCodeInterface) //Check if optCode is interface option
	if Cmp == 0 {                                   //if yes then remove it
		fmt.Println("Found opt code interface")
		OptionInterfacePadding := CalcPadding(4 + OptCodeLenghtInt)

		Optionsize := 4 + OptCodeLenghtInt + OptionInterfacePadding

		OtherOptions := IDB[16+Optionsize : len(IDB)-4]
		fmt.Println(OtherOptions)

		NewOptionInterface := GenerateNewOptionInterface(Reverse, HostName, Interface)
		Length := len(IDBType) + len(LinkType) + len(Reserved) + len(SnapLen) + len(NewOptionInterface) + len(OtherOptions) + 8
		LenByte := ItoBSlice(Length, 4, Reverse)

		NewIDB := concatMultipleSlices([][]byte{IDBType, LenByte, LinkType, Reserved, SnapLen, NewOptionInterface, OtherOptions, LenByte})

		// os.WriteFile(dt.String()+".NEW.IDB.dump", NewIDB, 0644)
		return NewIDB
	}
	return IDB
	// fmt.Println("--------------IDB Block---------------")
}

func CalcPadding(i int) int {
	Reminder := i % 4
	if Reminder > 0 {
		return 4 - Reminder
	}
	return 0
}

func GenerateNewOptionInterface(R bool, HostName, Interface string) []byte {
	OptionVal := []byte(HostName + "_" + Interface)
	OptionCode := make([]byte, 2)
	OptionLenghtInt := len(OptionVal)
	if R {
		OptionCode = []byte{02, 00}
	} else {
		OptionCode = []byte{00, 02}
	}
	OptionLenghtByte := ItoBSlice(OptionLenghtInt, 2, R)
	OptionInterfacePaddingCount := CalcPadding(4 + OptionLenghtInt)

	NewOption := concatMultipleSlices([][]byte{OptionCode, OptionLenghtByte, OptionVal})
	for i := 0; i < OptionInterfacePaddingCount; i++ {
		NewOption = append(NewOption, []byte{0}...)
	}
	return NewOption
}

func concatMultipleSlices[T any](slices [][]T) []T {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	result := make([]T, totalLen)
	var i int
	for _, s := range slices {
		i += copy(result[i:], s)
	}
	return result
}

func ItoBSlice(i, count int, R bool) []byte {
	var err error
	buf := new(bytes.Buffer)
	BytesReturn := make([]byte, count)
	if R {
		err = binary.Write(buf, binary.LittleEndian, uint32(i))
		BytesReturn = buf.Bytes()[:count]
	} else {
		err = binary.Write(buf, binary.BigEndian, uint32(i))
		BytesReturn = buf.Bytes()[len(buf.Bytes())-count:]
	}
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	return BytesReturn
}

func ReadFromEditCap(mu *sync.Mutex, R io.ReadCloser, HostName, DumpedInterface string) {
	var Rev bool
	var IDBInd byte
	for {

		bufRead := make([]byte, 65536)
		n, err := R.Read(bufRead)
		if err != nil {
			log.Fatalf("Error read buffer from dampcap: %s", err.Error())
		}
		if n > 0 {

			d := bufRead[:n]
			// dt := time.Now()
			// os.WriteFile(dt.String()+".dump", d, 0644)
			IsSHB, _, SHBHeader, IDBHeader, Reverse := AnalizeSHB(d)

			if IsSHB {

				mu.Lock()
				Rev = Reverse
				if !SHBPersist {
					SHBPersist = true
					WriteChan <- SHBHeader
				}
				IDBInd = IDBCount
				IDBCount++
				NewIDBHeader := RewriteIDB(IDBHeader, HostName, DumpedInterface, Rev)
				WriteChan <- NewIDBHeader
				mu.Unlock()

				// os.WriteFile(dt.String()+".L."+strconv.Itoa(L)+".SHB.dump", SHBHeader, 0644)
				// os.WriteFile(dt.String()+".L."+strconv.Itoa(L)+".IDB.dump", IDBHeader, 0644)
			} else {
				EditEPB(&d, Rev, IDBInd)
				// os.WriteFile(dt.String()+".EPBChanged.dump", d, 0644)
				WriteChan <- d
			}
		}
	}
}

func WriteToEditCap(W io.WriteCloser, PacketsChan chan []byte) {

	for {
		buf := <-PacketsChan
		_, err := W.Write(buf)
		if err != nil {
			log.Fatalf("Error write buffer to wireshark: %s", err.Error())
		}
	}
}

func ReadWireSharkErrors(R io.ReadCloser) {
	for {
		buf := make([]byte, 9000)
		n, err := R.Read(buf)
		if err != nil {
			log.Fatalf("Error read buffer from wireShark: %s", err.Error())
		}
		if n > 0 {
			d := buf[:n]
			if strings.Contains(string(d), "Capture Start") {
				time.Sleep(2 * time.Second)
				WiresharkStarted <- true
			}
			os.Stdout.Write(d)
		}
	}
}

func ReadFromWireshark(R io.ReadCloser) {
	for {
		buf := make([]byte, 9000)
		n, err := R.Read(buf)
		if err != nil {
			log.Fatalf("Error read buffer from wireShark: %s", err.Error())
		}
		if n > 0 {
			d := buf[:n]
			os.Stdout.Write(d)
		}
	}
}
func WriteToWireshark(W io.WriteCloser) {
	for {
		buf := <-WriteChan
		_, err := W.Write(buf)
		if err != nil {
			log.Fatalf("Error write buffer to wireshark: %s", err.Error())
		}
	}
}

func CheckValue(v HostsStruct) error {
	var err error
	if v.UserHost == "" || v.HostPort == "" || v.Key == "" || v.Interface == "" || v.PcapFilter == "" || v.Timeout == "" {
		err = errors.New("Some value are empty")
		return err
	}
	return err
}
func CheckConfig(Hosts FileConfig) error {
	var err error
	for _, v := range Hosts.Hosts {
		err = CheckValue(v)
		if err != nil {
			return err
		}
	}
	if Hosts.WindowsWireshark == "" || Hosts.MacOSWireshark == "" {
		err = errors.New("MacOSWireshark or WindowsWireshark field is empty")
		return err
	}
	return err
}

func init() {
	jsonFile, err := os.Open("hosts.conf")
	if err != nil {
		log.Fatalf("Error open file hosts.conf: %s", err.Error())
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &Hosts)
	if err != nil {
		log.Fatalf("Error parse json hosts.conf: %s", err.Error())
	}
	err = CheckConfig(Hosts)
	if err != nil {
		log.Fatalf("Error in config: %s", err.Error())
	}
}

func main() {
	var WiresharkPath string

	WriteChan = make(chan []byte)
	WiresharkStarted = make(chan bool)

	switch OS := runtime.GOOS; OS {
	case "darwin":
		WiresharkPath = Hosts.MacOSWireshark
	case "linux":
		WiresharkPath = "wireshark"
	case "windows":
		WiresharkPath = Hosts.WindowsWireshark
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		cmdWires := exec.Command(WiresharkPath, "-k", "-i", "-")
		stdinW, errIn := cmdWires.StdinPipe()
		if errIn != nil {
			log.Fatalf("Error for in pipe for command wireshark: %s, Err: %s", WiresharkPath, errIn.Error())
		}
		stdoutW, errOut := cmdWires.StdoutPipe()
		if errOut != nil {
			log.Fatalf("Error for out pipe for command wireshark: %s, Err: %s", WiresharkPath, errOut.Error())
		}
		stdoutErr, _ := cmdWires.StderrPipe()

		if errShark := cmdWires.Start(); nil != errShark {
			log.Fatalf("Error starting program: %s, %s", cmdWires.Path, errShark.Error())
		}
		go WriteToWireshark(stdinW)
		go ReadFromWireshark(stdoutW)
		go ReadWireSharkErrors(stdoutErr)
	}

	<-WiresharkStarted

	for i, v := range Hosts.Hosts {
		SShCommand := fmt.Sprintf(Command, v.Key, v.UserHost, v.HostPort, v.Timeout, v.Interface, v.PcapFilter)
		PacketsChans[i] = make(chan []byte)

		if runtime.GOOS == "windows" {
			Cmds[i] = exec.Command("powershell", "-nologo", "-NoProfile", SShCommand)
			cmdEditCap[i] = exec.Command(filepath.Dir(WiresharkPath)+"\\dumpcap.exe", "-i", "-", "-w", "-", "-q")
		} else {
			Cmds[i] = exec.Command("bash", "-c", SShCommand)
			cmdEditCap[i] = exec.Command("bash", "-c", "dumpcap -i - -w - -q")
		}
		editcapStdout, editcaperr := cmdEditCap[i].StdoutPipe()
		editcapStdIn, _ := cmdEditCap[i].StdinPipe()
		if editcaperr != nil {
			log.Fatalf("Error for pipe for command: %s, Err: %s", "dumpcap", editcaperr.Error())
		}
		if editcaperr = cmdEditCap[i].Start(); nil != editcaperr {
			log.Fatalf("Error starting program: %s, %s", cmdEditCap[i].Path, editcaperr.Error())
		}
		go ReadFromEditCap(&Mu, editcapStdout, v.UserHost, v.Interface)
		go WriteToEditCap(editcapStdIn, PacketsChans[i])

		stdout, err := Cmds[i].StdoutPipe()

		if err != nil {
			log.Fatalf("Error for pipe for command: %s, Err: %s", SShCommand, err.Error())
		}

		if err = Cmds[i].Start(); nil != err {
			log.Fatalf("Error starting program: %s, %s", Cmds[i].Path, err.Error())
		}

		go ReadfromBufferOutChan(stdout, PacketsChans[i])

	}

	for _, v := range Cmds {
		v.Wait()
	}
}
