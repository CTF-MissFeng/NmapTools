package main

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/PuerkitoBio/goquery"
	"github.com/panjf2000/ants/v2"
)

var wg sync.WaitGroup
var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var client = &http.Client{
	Transport: tr,
	Timeout:time.Duration(int64(TimeOut))*time.Second,
}

type HttpInfoStruct struct {
	url string
	title string
	statuscode string
}

// 保存HTTP探测结果
var HttpInfoStructs []HttpInfoStruct

// 保存socket数据结果
type SocketInfoStruct struct {
	Ip string
	Command string
	Command_Result string
}

var SocketInfoMap = make(map[string][]SocketInfoStruct, 10)

var SocketTimeout = 3
var Lock sync.Mutex
// Timestamp represents time as a UNIX timestamp in seconds.
type Timestamp time.Time

// str2time converts a string containing a UNIX timestamp to to a time.Time.
func (t *Timestamp) str2time(s string) error {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(ts, 0))
	return nil
}

// time2str formats the time.Time value as a UNIX timestamp string.
// XXX these might also need to be changed to pointers. See str2time and UnmarshalXMLAttr.
func (t Timestamp) time2str() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.time2str()), nil
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	return t.str2time(string(b))
}

func (t Timestamp) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.time2str()}, nil
}

func (t *Timestamp) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.str2time(attr.Value)
}

// NmapRun is contains all the data for a single nmap scan.
type NmapRun struct {
	Scanner          string         `xml:"scanner,attr" json:"scanner"`
	Args             string         `xml:"args,attr" json:"args"`
	Start            Timestamp      `xml:"start,attr" json:"start"`
	StartStr         string         `xml:"startstr,attr" json:"startstr"`
	Version          string         `xml:"version,attr" json:"version"`
	ProfileName      string         `xml:"profile_name,attr" json:"profile_name"`
	XMLOutputVersion string         `xml:"xmloutputversion,attr" json:"xmloutputversion"`
	ScanInfo         ScanInfo       `xml:"scaninfo" json:"scaninfo"`
	Verbose          Verbose        `xml:"verbose" json:"verbose"`
	Debugging        Debugging      `xml:"debugging" json:"debugging"`
	TaskBegin        []Task         `xml:"taskbegin" json:"taskbegin"`
	TaskProgress     []TaskProgress `xml:"taskprogress" json:"taskprogress"`
	TaskEnd          []Task         `xml:"taskend" json:"taskend"`
	PreScripts       []Script       `xml:"prescript>script" json:"prescripts"`
	PostScripts      []Script       `xml:"postscript>script" json:"postscripts"`
	Hosts            []Host         `xml:"host" json:"hosts"`
	Targets          []Target       `xml:"target" json:"targets"`
	RunStats         RunStats       `xml:"runstats" json:"runstats"`
}

// ScanInfo contains informational regarding how the scan
// was run.
type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	NumServices int    `xml:"numservices,attr" json:"numservices"`
	Services    string `xml:"services,attr" json:"services"`
	ScanFlags   string `xml:"scanflags,attr" json:"scanflags"`
}

// Verbose contains the verbosity level for the Nmap scan.
type Verbose struct {
	Level int `xml:"level,attr" json:"level"`
}

// Debugging contains the debugging level for the Nmap scan.
type Debugging struct {
	Level int `xml:"level,attr" json:"level"`
}

// Task contains information about started and stopped Nmap tasks.
type Task struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	ExtraInfo string    `xml:"extrainfo,attr" json:"extrainfo"`
}

// TaskProgress contains information about the progression of a Task.
type TaskProgress struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	Percent   float32   `xml:"percent,attr" json:"percent"`
	Remaining int       `xml:"remaining,attr" json:"remaining"`
	Etc       Timestamp `xml:"etc,attr" json:"etc"`
}

// Target is found in the Nmap xml spec. I have no idea what it
// actually is.
type Target struct {
	Specification string `xml:"specification,attr" json:"specification"`
	Status        string `xml:"status,attr" json:"status"`
	Reason        string `xml:"reason,attr" json:"reason"`
}

// Host contains all information about a single host.
type Host struct {
	StartTime     Timestamp     `xml:"starttime,attr" json:"starttime"`
	EndTime       Timestamp     `xml:"endtime,attr" json:"endtime"`
	Comment       string        `xml:"comment,attr" json:"comment"`
	Status        Status        `xml:"status" json:"status"`
	Addresses     []Address     `xml:"address" json:"addresses"`
	Hostnames     []Hostname    `xml:"hostnames>hostname" json:"hostnames"`
	Smurfs        []Smurf       `xml:"smurf" json:"smurfs"`
	Ports         []Port        `xml:"ports>port" json:"ports"`
	ExtraPorts    []ExtraPorts  `xml:"ports>extraports" json:"extraports"`
	Os            Os            `xml:"os" json:"os"`
	Distance      Distance      `xml:"distance" json:"distance"`
	Uptime        Uptime        `xml:"uptime" json:"uptime"`
	TcpSequence   TcpSequence   `xml:"tcpsequence" json:"tcpsequence"`
	IpIdSequence  IpIdSequence  `xml:"ipidsequence" json:"ipidsequence"`
	TcpTsSequence TcpTsSequence `xml:"tcptssequence" json:"tcptssequence"`
	HostScripts   []Script      `xml:"hostscript>script" json:"hostscripts"`
	Trace         Trace         `xml:"trace" json:"trace"`
	Times         Times         `xml:"times" json:"times"`
}

// Status is the host's status. Up, down, etc.
type Status struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
}

// Address contains a IPv4 or IPv6 address for a Host.
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addrtype"`
	Vendor   string `xml:"vendor,attr" json:"vendor"`
}

// Hostname is a single name for a Host.
type Hostname struct {
	Name string `xml:"name,attr" json:"name"`
	Type string `xml:"type,attr" json:"type"`
}

// Smurf contains repsonses from a smurf attack. I think.
// Smurf attacks, really?
type Smurf struct {
	Responses string `xml:"responses,attr" json:"responses"`
}

// ExtraPorts contains the information about the closed|filtered ports.
type ExtraPorts struct {
	State   string   `xml:"state,attr" json:"state"`
	Count   int      `xml:"count,attr" json:"count"`
	Reasons []Reason `xml:"extrareasons" json:"reasons"`
}
type Reason struct {
	Reason string `xml:"reason,attr" json:"reason"`
	Count  int    `xml:"count,attr" json:"count"`
}

// Port contains all the information about a scanned port.
type Port struct {
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	PortId   int      `xml:"portid,attr" json:"id"`
	State    State    `xml:"state" json:"state"`
	Owner    Owner    `xml:"owner" json:"owner"`
	Service  Service  `xml:"service" json:"service"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

// State contains information about a given ports
// status. State will be open, closed, etc.
type State struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
	ReasonIP  string  `xml:"reason_ip,attr" json:"reason_ip"`
}

// Owner contains the name of Port.Owner.
type Owner struct {
	Name string `xml:"name,attr" json:"name"`
}

// Service contains detailed information about a Port's
// service details.
type Service struct {
	Name       string `xml:"name,attr" json:"name"`
	Conf       int    `xml:"conf,attr" json:"conf"`
	Method     string `xml:"method,attr" json:"method"`
	Version    string `xml:"version,attr" json:"version"`
	Product    string `xml:"product,attr" json:"product"`
	ExtraInfo  string `xml:"extrainfo,attr" json:"extrainfo"`
	Tunnel     string `xml:"tunnel,attr" json:"tunnel"`
	Proto      string `xml:"proto,attr" json:"proto"`
	Rpcnum     string `xml:"rpcnum,attr" json:"rpcnum"`
	Lowver     string `xml:"lowver,attr" json:"lowver"`
	Highver    string `xml:"hiver,attr" json:"hiver"`
	Hostname   string `xml:"hostname,attr" json:"hostname"`
	OsType     string `xml:"ostype,attr" json:"ostype"`
	DeviceType string `xml:"devicetype,attr" json:"devicetype"`
	ServiceFp  string `xml:"servicefp,attr" json:"servicefp"`
	CPEs       []CPE  `xml:"cpe" json:"cpes"`
}

// CPE (Common Platform Enumeration) is a standardized way to name software
// applications, operating systems, and hardware platforms.
type CPE string

// Script contains information from Nmap Scripting Engine.
type Script struct {
	Id       string    `xml:"id,attr" json:"id"`
	Output   string    `xml:"output,attr" json:"output"`
	Tables   []Table   `xml:"table" json:"tables"`
	Elements []Element `xml:"elem" json:"elements"`
}

// Table contains the output of the script in a more parse-able form.
// ToDo: This should be a map[string][]string
type Table struct {
	Key      string    `xml:"key,attr" json:"key"`
	Elements []Element `xml:"elem" json:"elements"`
	Table    []Table   `xml:"table" json:"tables"`
}

// Element contains the output of the script, with detailed information
type Element struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

// Os contains the fingerprinted operating system for a Host.
type Os struct {
	PortsUsed      []PortUsed      `xml:"portused" json:"portsused"`
	OsMatches      []OsMatch       `xml:"osmatch" json:"osmatches"`
	OsFingerprints []OsFingerprint `xml:"osfingerprint" json:"osfingerprints"`
}

// PortsUsed is the port used to fingerprint a Os.
type PortUsed struct {
	State  string `xml:"state,attr" json:"state"`
	Proto  string `xml:"proto,attr" json:"proto"`
	PortId int    `xml:"portid,attr" json:"portid"`
}

// OsClass contains vendor information for an Os.
type OsClass struct {
	Vendor   string `xml:"vendor,attr" json:"vendor"`
	OsGen    string `xml"osgen,attr"`
	Type     string `xml:"type,attr" json:"type"`
	Accuracy string `xml:"accurancy,attr" json:"accurancy"`
	OsFamily string `xml:"osfamily,attr" json:"osfamily"`
	CPEs     []CPE  `xml:"cpe" json:"cpes"`
}

// OsMatch contains detailed information regarding a Os fingerprint.
type OsMatch struct {
	Name      string    `xml:"name,attr" json:"name"`
	Accuracy  string    `xml:"accuracy,attr" json:"accuracy"`
	Line      string    `xml:"line,attr" json:"line"`
	OsClasses []OsClass `xml:"osclass" json:"osclasses"`
}

// OsFingerprint is the actual fingerprint string.
type OsFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr" json:"fingerprint"`
}

// Distance is the amount of hops to a particular host.
type Distance struct {
	Value int `xml:"value,attr" json:"value"`
}

// Uptime is the amount of time the host has been up.
type Uptime struct {
	Seconds  int    `xml:"seconds,attr" json:"seconds"`
	Lastboot string `xml:"lastboot,attr" json:"lastboot"`
}

// TcpSequence contains information regarding the detected tcp sequence.
type TcpSequence struct {
	Index      int    `xml:"index,attr" json:"index"`
	Difficulty string `xml:"difficulty,attr" json:"difficulty"`
	Values     string `xml:"vaules,attr" json:"vaules"`
}

// Sequence contains information regarding the detected X sequence.
type Sequence struct {
	Class  string `xml:"class,attr" json:"class"`
	Values string `xml:"values,attr" json:"values"`
}
type IpIdSequence Sequence
type TcpTsSequence Sequence

// Trace contains the hops to a Host.
type Trace struct {
	Proto string `xml:"proto,attr" json:"proto"`
	Port  int    `xml:"port,attr" json:"port"`
	Hops  []Hop  `xml:"hop" json:"hops"`
}

// Hop is a ip hop to a Host.
type Hop struct {
	TTL    float32 `xml:"ttl,attr" json:"ttl"`
	RTT    float32 `xml:"rtt,attr" json:"rtt"`
	IPAddr string  `xml:"ipaddr,attr" json:"ipaddr"`
	Host   string  `xml:"host,attr" json:"host"`
}

// Times contains time statistics for an Nmap scan.
type Times struct {
	SRTT string `xml:"srtt,attr" json:"srtt"`
	RTT  string `xml:"rttvar,attr" json:"rttv"`
	To   string `xml:"to,attr" json:"to"`
}

// RunStats contains statistics for a
// finished Nmap scan.
type RunStats struct {
	Finished Finished  `xml:"finished" json:"finished"`
	Hosts    HostStats `xml:"hosts" json:"hosts"`
}

// Finished contains detailed statistics regarding
// a finished Nmap scan.
type Finished struct {
	Time     Timestamp `xml:"time,attr" json:"time"`
	TimeStr  string    `xml:"timestr,attr" json:"timestr"`
	Elapsed  float32   `xml:"elapsed,attr" json:"elapsed"`
	Summary  string    `xml:"summary,attr" json:"summary"`
	Exit     string    `xml:"exit,attr" json:"exit"`
	ErrorMsg string    `xml:"errormsg,attr" json:"errormsg"`
}

// HostStats contains the amount of up and down hosts and the total count.
type HostStats struct {
	Up    int `xml:"up,attr" json:"up"`
	Down  int `xml:"down,attr" json:"down"`
	Total int `xml:"total,attr" json:"total"`
}

type Nmap struct {
	FileName string
	NmapRun
}

// 解析nmap扫描结果
func (n *Nmap)Parse() (error) {
	file, err := ioutil.ReadFile(n.FileName)
	if err != nil {
		err = errors.New(fmt.Sprintf("[-]读取%s文件内容失败:%s", n.FileName, err))
		return err
	}
	r := &NmapRun{}
	err = xml.Unmarshal(file, r)
	n.NmapRun = *r
	return err
}

// 导出解析结果到xlsx表格中
func (n *Nmap)ToXlsx(output string)(error){
	book := excelize.NewFile()
	book.SetSheetName("Sheet1", "nmap解析结果") // 设置工作表名
	book.SetCellValue("nmap解析结果", "A1", "IP地址") // 设置单元格的值
	book.SetCellValue("nmap解析结果", "B1", "端口")
	book.SetCellValue("nmap解析结果", "C1", "协议")
	book.SetCellValue("nmap解析结果", "D1", "服务")
	book.SetCellValue("nmap解析结果", "E1", "服务详情")
	book.SetCellValue("nmap解析结果", "F1", "版本")
	index := 2
	ipIndex := 1
	for _, v := range n.NmapRun.Hosts{
		ipIndex++
		for _, portSlice := range v.Ports {
			if portSlice.State.State != "open"{ // 过滤未开放的端口
				continue
			}
			book.SetCellValue("nmap解析结果", "A"+strconv.Itoa(index), v.Addresses[0].Addr)
			book.SetCellValue("nmap解析结果", "B"+strconv.Itoa(index), portSlice.PortId)
			book.SetCellValue("nmap解析结果", "C"+strconv.Itoa(index), portSlice.Protocol)
			book.SetCellValue("nmap解析结果", "D"+strconv.Itoa(index), portSlice.Service.Name)
			book.SetCellValue("nmap解析结果", "E"+strconv.Itoa(index), portSlice.Service.Product)
			book.SetCellValue("nmap解析结果", "F"+strconv.Itoa(index), portSlice.Service.Version)
			index++
		}
	}
	book.SetActiveSheet(0) //  设置工作簿的默认工作表
	book.SetColWidth("nmap解析结果", "A", "A", 15) // 设置列宽度
	book.SetColWidth("nmap解析结果", "B", "B", 8)
	book.SetColWidth("nmap解析结果", "C", "D", 12)
	book.SetColWidth("nmap解析结果", "E", "F", 18)
	log.Printf("[+]解析成功，共计%d条IP及%d条端口数据", ipIndex, index-1)
	err := book.SaveAs(output + ".xlsx")
	return err
}

// 探测HTTP服务
func getHttp(get_url string){
	http_url := "http://" + get_url
	https_url := "https://" + get_url
	log.Printf("[+]开始Http服务探测 %s", http_url)
	defer wg.Done()
	resp, err := client.Get(http_url)
	var tmp_http HttpInfoStruct
	if err != nil {
		resp, err = client.Get(https_url)
		if err != nil {
			log.Printf("[-]不是有效的web服务,errer:%s",err)
			return
		} else {
			tmp_http.url = https_url
		}
	}else {
		tmp_http.url = http_url
	}
	tmp_http.statuscode = strconv.Itoa(resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("[-] %s 获取title失败,error:%s", tmp_http.url, err.Error())
		HttpInfoStructs = append(HttpInfoStructs, tmp_http)
		log.Printf("[+] %s %s", tmp_http.url, tmp_http.statuscode)
		return
	}
	doc.Find("title").Each(func(i int, selection *goquery.Selection) {
		tmp_http.title = selection.Text()
	})
	Lock.Lock()
	HttpInfoStructs = append(HttpInfoStructs, tmp_http)
	Lock.Unlock()
	log.Printf("[+] %s %s %s", tmp_http.url, tmp_http.statuscode, tmp_http.title)
	defer func(){
		if resp != nil {
			resp.Body.Close()
		}
	}()
}

// HTTP探测主任务调度
func(n *Nmap)HttpProbe(thread int){
	url_chan := make(chan string, 50)
	go func() { // HTTP探测 生产者
		for _, v := range n.NmapRun.Hosts{
			for _, portSlice := range v.Ports {
				if portSlice.State.State != "open"{ // 过滤未开放的端口
					continue
				}
				url_port := v.Addresses[0].Addr + ":" + strconv.Itoa(portSlice.PortId)
				url_chan <- url_port
			}
		}
		defer close(url_chan)
	}()
	chairPool, _ := ants.NewPoolWithFunc(thread, func(i interface{}) {
		getHttp(i.(string))
	})  // 协程池
	defer chairPool.Release()
	func() { // HTTP探测 消费者
		for {
			i, ok := <-url_chan
			if !ok {
				break
			}
			wg.Add(1)
			chairPool.Invoke(i)
		}
	}()
	wg.Wait()
	err := httpToXlsx(n.FileName)
	if err != nil {
		log.Fatal("[-]保存http服务探测失败,error:",err.Error())
	}
	log.Printf("[+]http服务探测保存成功，请查看 %s", n.FileName + "_http探测结果.xlsx")
}

// 导出http探测结果
func httpToXlsx(filename string)(error){
	book := excelize.NewFile()
	book.SetSheetName("Sheet1", "Http服务探测结果") // 设置工作表名
	book.SetCellValue("Http服务探测结果", "A1", "Url") // 设置单元格的值
	book.SetCellValue("Http服务探测结果", "B1", "Title")
	book.SetCellValue("Http服务探测结果", "C1", "StatusCode")
	Index := 1
	for _, tmp := range HttpInfoStructs{
		Index++
		book.SetCellValue("Http服务探测结果", "A"+strconv.Itoa(Index), tmp.url)
		book.SetCellValue("Http服务探测结果", "B"+strconv.Itoa(Index), tmp.title)
		book.SetCellValue("Http服务探测结果", "C"+strconv.Itoa(Index), tmp.statuscode)
	}
	book.SetActiveSheet(0) //  设置工作簿的默认工作表
	book.SetColWidth("Http服务探测结果", "A", "A", 40) // 设置列宽度
	book.SetColWidth("Http服务探测结果", "B", "B", 30)
	book.SetColWidth("Http服务探测结果", "C", "C", 15)
	err := book.SaveAs(filename + "_http探测结果.xlsx")
	return err
}

// socket数据获取
func getSocket(ip_port string){
	slice1 := strings.Split(ip_port,"|")
	if len(slice1)!=2{
		log.Printf("[-]错误的socket命令：%s\n", ip_port)
		return
	}
	defer wg.Done()
	connTimeout := time.Duration(int64(SocketTimeout))*time.Second
	conn, err := net.DialTimeout("tcp", slice1[0], connTimeout)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		log.Printf("[-] %s socket连接失败, error:%s\n", slice1[0], err.Error())
		return
	}
	writeTimeout := 5*time.Second
	err = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err != nil {
		log.Printf("[-] %s 写入超时设置失败:%s\n", slice1[0], err.Error())
		return
	}
	_, err = conn.Write([]byte(slice1[1]))
	if err != nil {
		log.Printf("[-] %s 发送命令失败 %s\n", slice1[0], err.Error())
		return
	}
	buf := [512]byte{}
	readTimeout := 5*time.Second
	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		log.Printf("[-] %s 读取超时设置失败:%s\n", slice1[0], err.Error())
		return
	}
	n, err := conn.Read(buf[:])
	if err != nil {
		log.Printf("[-] %s 获取数据失败 error:%s\n", slice1[0], err.Error())
		return
	}
	result := string(buf[:n])
	//log.Printf("[-] %s 获取数据成功：%s\n", slice1[0], result)
	var tmp_socket SocketInfoStruct
	tmp_socket.Ip = slice1[0]
	tmp_socket.Command = slice1[1]
	tmp_socket.Command_Result = result
	Lock.Lock()
	tmp_old, ok := SocketInfoMap[slice1[0]]
	if !ok{
		SocketInfoMap[slice1[0]] = []SocketInfoStruct{tmp_socket}
	} else {
		SocketInfoMap[slice1[0]] = append(tmp_old, tmp_socket)
	}
	Lock.Unlock()
}

// socket探测主任务调度
func(n *Nmap)SocketProbe(command string, thread int, socket_timeout int){
	SocketTimeout = socket_timeout
	ip_chan := make(chan string, 50)
	command_slice := strings.Split(command,",")
	if len(command_slice)<=1{
		log.Fatal("[-]Socket数据探测Command命令错误，请以,号分割命令")
	}
	go func() { // socket探测 生产者
		for _, v := range n.NmapRun.Hosts{
			for _, portSlice := range v.Ports {
				if portSlice.State.State != "open"{ // 过滤未开放的端口
					continue
				}
				for _, tmp_command := range command_slice{
					url_port := v.Addresses[0].Addr + ":" + strconv.Itoa(portSlice.PortId) + "|" + tmp_command
					ip_chan <- url_port
				}

			}
		}
		defer close(ip_chan)
	}()
	chairPool, _ := ants.NewPoolWithFunc(thread, func(i interface{}) {
		getSocket(i.(string))
	})  // 协程池
	defer chairPool.Release()
	func() { // Socket探测 消费者
		for {
			i, ok := <-ip_chan
			if !ok {
				break
			}
			wg.Add(1)
			chairPool.Invoke(i)
		}
	}()
	wg.Wait()
	err := scoketToXlsx(n.FileName)
	if err != nil {
		log.Fatal("[-]保存socket服务探测失败,error:",err.Error())
	}
	log.Printf("[+]socket服务探测保存成功，请查看 %s", n.FileName + "_socket探测结果.xlsx")
}

// 导出socket探测结果
func scoketToXlsx(filename string)(error){
	book := excelize.NewFile()
	book.SetSheetName("Sheet1", "socket服务探测结果") // 设置工作表名
	book.SetCellValue("socket服务探测结果", "A1", "IP") // 设置单元格的值
	book.SetCellValue("socket服务探测结果", "B1", "Command")
	book.SetCellValue("socket服务探测结果", "C1", "Result")
	Index := 1
	for _, v := range SocketInfoMap{
		for _, tmp := range v{
			Index++
			book.SetCellValue("socket服务探测结果", "A"+strconv.Itoa(Index), tmp.Ip)
			book.SetCellValue("socket服务探测结果", "B"+strconv.Itoa(Index), tmp.Command)
			book.SetCellValue("socket服务探测结果", "C"+strconv.Itoa(Index), tmp.Command_Result)
		}
	}
	book.SetActiveSheet(0) //  设置工作簿的默认工作表
	book.SetColWidth("socket服务探测结果", "A", "A", 20) // 设置列宽度
	book.SetColWidth("socket服务探测结果", "B", "B", 12)
	book.SetColWidth("socket服务探测结果", "C", "C", 40)
	err := book.SaveAs(filename + "_socket探测结果.xlsx")
	return err
}