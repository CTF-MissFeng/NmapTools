package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

var nmaptool Nmap
var TimeOut = 5

func main() {
	app := &cli.App{
		Name:                   "NmapTools",
		Version:                "1.0",
		Usage:                  "解析导出nmap扫描结果、对扫描结果进行HTTP探测、socket端口数据获取、常规服务破解",
		UsageText:              "NmapTools [参数选项] --file参数为必须",
		EnableBashCompletion:   true,
		Copyright:              "版权所有：MissFeng  QQ：1767986993",
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "file",
				Aliases: []string{"f"},
				Usage: "指定要解析的Nmap扫描结果xml文件路径",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "output",
				Aliases: []string{"o"},
				Usage: "导出Nmap解析结果(xlsx文档)",
			},
			&cli.BoolFlag{
				Name:  "web",
				Aliases: []string{"w"},
				Usage: "解析nmap扫描结果,进行web服务探测",
				Value: true,
			},
			&cli.IntFlag{
				Name:  "timeout",
				Aliases: []string{"t"},
				Usage: "web服务探测超时时间",
				Value: 5,
			},
			&cli.IntFlag{
				Name:  "Coroutine",
				Aliases: []string{"c"},
				Usage: "协程并发数(web探测和socket探测)",
				Value: 20,
			},
			&cli.BoolFlag{
				Name:  "socket",
				Aliases: []string{"s"},
				Usage: "解析nmap扫描结果,进行Socket数据获取",
				Value: true,
			},
			&cli.StringFlag{
				Name:  "command",
				Aliases: []string{"cmd"},
				Usage: "Socket数据发送命令,以,号分割",
				Value: "\n,ls\n,help\n,envi\n,info\n,dir\n,id\n,?\n",
			},
			&cli.IntFlag{
				Name:  "stimeout",
				Aliases: []string{"st"},
				Usage: "socket数据探测超时时间",
				Value: 5,
			},
		},
		Action: func(c *cli.Context) error {
			if c.IsSet("file")&&c.IsSet("output"){
				nmaptool.FileName = c.String("file")
				err := nmaptool.Parse()
				if err != nil {
					log.Fatal(err)
				}
				err = nmaptool.ToXlsx(c.String("output"))
				if err != nil {
					log.Fatal(err)
				}else {
					log.Printf("[+]导出解析结果成功，请查看%s文件", c.String("output")+".xlsx")
				}
			} else if c.IsSet("file")&&c.IsSet("web"){
				TimeOut = c.Int("timeout")
				nmaptool.FileName = c.String("file")
				err := nmaptool.Parse()
				if err != nil {
					log.Fatal(err)
				}
				nmaptool.HttpProbe(c.Int("Coroutine"))
			} else if c.IsSet("file")&&c.IsSet("socket"){
				nmaptool.FileName = c.String("file")
				err := nmaptool.Parse()
				if err != nil {
					log.Fatal(err)
				}
				nmaptool.SocketProbe(c.String("command"), c.Int("Coroutine"), c.Int("stimeout"))
			}
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
