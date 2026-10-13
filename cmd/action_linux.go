package cmd

import (
	"fmt"
	"time"

	"github.com/AnixOps/anix-agent/v5/common/exec"
	"github.com/spf13/cobra"
)

var (
	startCommand = cobra.Command{
		Use:   "start",
		Short: "Start AnixOps Agent service",
		Run:   startHandle,
	}
	stopCommand = cobra.Command{
		Use:   "stop",
		Short: "Stop AnixOps Agent service",
		Run:   stopHandle,
	}
	restartCommand = cobra.Command{
		Use:   "restart",
		Short: "Restart AnixOps Agent service",
		Run:   restartHandle,
	}
	logCommand = cobra.Command{
		Use:   "log",
		Short: "Output AnixOps Agent log",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("journalctl", "-u", serviceName, "-e", "--no-pager", "-f")
		},
	}
)

func init() {
	command.AddCommand(&startCommand)
	command.AddCommand(&stopCommand)
	command.AddCommand(&restartCommand)
	command.AddCommand(&logCommand)
}

func startHandle(_ *cobra.Command, _ []string) {
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err(productName + " 启动失败"))
		return
	}
	if r {
		fmt.Println(Ok(productName + " 已运行，无需再次启动，如需重启请选择重启"))
	}
	_, err = exec.RunCommandByShell("systemctl start " + serviceName)
	if err != nil {
		fmt.Println(Err("exec start cmd error: ", err))
		fmt.Println(Err(productName + " 启动失败"))
		return
	}
	time.Sleep(time.Second * 3)
	r, err = checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err(productName + " 启动失败"))
	}
	if !r {
		fmt.Println(Err(productName + " 可能启动失败，请稍后使用 anix-agent log 查看日志信息"))
		return
	}
	fmt.Println(Ok(productName + " 启动成功，请使用 anix-agent log 查看运行日志"))
}

func stopHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl stop " + serviceName)
	if err != nil {
		fmt.Println(Err("exec stop cmd error: ", err))
		fmt.Println(Err(productName + " 停止失败"))
		return
	}
	time.Sleep(2 * time.Second)
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error:", err))
		fmt.Println(Err(productName + " 停止失败"))
		return
	}
	if r {
		fmt.Println(Err(productName + " 停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息"))
		return
	}
	fmt.Println(Ok(productName + " 停止成功"))
}

func restartHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl restart " + serviceName)
	if err != nil {
		fmt.Println(Err("exec restart cmd error: ", err))
		fmt.Println(Err(productName + " 重启失败"))
		return
	}
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err(productName + " 重启失败"))
		return
	}
	if !r {
		fmt.Println(Err(productName + " 可能启动失败，请稍后使用 anix-agent log 查看日志信息"))
		return
	}
	fmt.Println(Ok(productName + " 重启成功"))
}
