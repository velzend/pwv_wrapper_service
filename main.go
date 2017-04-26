/*
 *
 * Copyright 2017, Dennis van Velzen (and friends).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither in my name of nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package main

import (
	"net/http"
	"os/exec"
	"time"
	"io/ioutil"
	"fmt"
	"os"
	"errors"
	"strings"
	"bytes"
	"syscall"
	"regexp"
	"log"
	"gopkg.in/yaml.v2"
	"github.com/gin-gonic/gin"
	"github.com/aviddiviner/gin-limit"
)

const version = "0.1.1"

type logWriter struct {
}

// format logs similar to GIN
func (writer logWriter) Write(bytes []byte) (int, error) {
	t := time.Now()
	return fmt.Printf("[PWV] %d/%02d/%02d - %02d:%02d:%02d %s",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), bytes)
}

var isValidAccount_name = regexp.MustCompile(`^[0-9a-zA-Z-_]+$`).MatchString

type Configuration struct {
	PWVHost                       string    `yaml:"password_vault_pwv_host"`
	PWVCLIPasswordSDK_CMD         string    `yaml:"password_vault_clipasswordsdk_cmd"`
	PWVCLIPasswordSDK_CMD_timeout uint64    `yaml:"password_vault_clipasswordsdk_cmd_timeout"`
	PWVWSUAccountName             string    `yaml:"password_vault_wsu_account_name"`
	PWVUnmanagedSafe              string    `yaml:"password_vault_pwv_unmanaged_safe"`
	PWVUnmanagedPlatformID        string    `yaml:"password_vault_pwv_unmanaged_platform_id"`
	PWVManagedPlatformID          string    `yaml:"password_vault_pwv_managed_platform_id"`
	PWVWSUSafe                    string    `yaml:"password_vault_pwv_wsu_safe"`
	PWVAppID                      string    `yaml:"password_vault_app_id"`
	PWVUsername                   string    `yaml:"password_vault_pwv_username"`
	PWVManagedSafe                string    `yaml:"password_vault_pwv_managed_safe"`
	RouterAddress                 string    `yaml:"service_bind_address"`
	RouterSocket                  uint16    `yaml:"service_bind_socket"`
}

type Result struct {
	ok        bool
	stdout    string
	stderr    string
	exit_code int
	elapsed   time.Duration
}

func usage() {
	fmt.Fprint(os.Stderr, "make sure the config.yaml exists, no arguments reguired\n")
	os.Exit(2)
}

func init() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
}

func saveConfig(c Configuration, filename string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, b, 0644)
}

func loadConfig(filename string) (Configuration, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return Configuration{}, err
	}

	var c Configuration
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		return Configuration{}, err
	}

	return c, nil
}

func createMockConfig() Configuration {
	return Configuration{
		PWVHost:                       "",
		PWVCLIPasswordSDK_CMD:         "",
		PWVCLIPasswordSDK_CMD_timeout: 20000,
		PWVWSUAccountName:             "",
		PWVUnmanagedSafe:              "",
		PWVUnmanagedPlatformID:        "",
		PWVManagedPlatformID:          "",
		PWVWSUSafe:                    "",
		PWVAppID:                      "",
		PWVUsername:                   "",
		PWVManagedSafe:                "",
		RouterAddress:                 "127.0.0.1",
		RouterSocket:                  3000,
	}
}

func PWVCLICMD(time_out uint64, pwv_cmd string,
	pwv_appID string, pwv_safe string, account_name string) (r Result, err error) {
	var (
		out_buf, err_buf bytes.Buffer
		waitStatus       syscall.WaitStatus
	)

	start := time.Now()
	r.ok = false

	// Create the command
	pwv_args := []string{"GetPassword",
			     "-p", "AppDescs.AppID=" + pwv_appID,
			     "-p", "Query=Safe=" + pwv_safe + ";Folder=root;Object=" + account_name,
			     "-o", "Password"}
	cmd := exec.Command(pwv_cmd, pwv_args...)

	// Use the current OS environment variables
	cmd.Env = os.Environ()

	log.Printf("Exec: %s", cmd.Args)

	// Now we can buffer to get the STDOUT and STDERR.
	cmd.Stdout = &out_buf
	cmd.Stderr = &err_buf

	// Lets start the command
	cmd.Start()

	// Make a channel
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-time.After(time.Millisecond * time.Duration(time_out)):
		if err := cmd.Process.Kill(); err != nil {
			err = errors.New(fmt.Sprint("failed to kill: ", err))
		}
		err = errors.New("process killed as timeout reached")

	case err := <-done:
		if exit_error, ok := err.(*exec.ExitError); ok {
			waitStatus = exit_error.Sys().(syscall.WaitStatus)
			r.exit_code = int(waitStatus.ExitStatus())
		}

		if err != nil {
			err = errors.New(fmt.Sprintf("process done with error = %v", err))
		} else {
			r.ok = true
		}

	}

	r.stdout = strings.TrimSpace(out_buf.String())
	r.stderr = strings.TrimSpace(err_buf.String())

	r.elapsed = time.Since(start)

	return
}

func main() {

	log.Printf("Starting service (version: %s)...", version)
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Printf("While loading configuration an exception occurred: %s", err)
		log.Println("Creating new empty configuration file...")
		err := saveConfig(createMockConfig(), "config.yaml")
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal("Please enter details in configuration file according your environment")
	}

	// check configuration for invalid parameters
	if cfg.RouterSocket == 0 {
		log.Fatal("Please specify valid socket for router")
	}

	if cfg.PWVCLIPasswordSDK_CMD_timeout == 0 {
		log.Fatal("Please specify valid command time-out")
	}

	log.Printf("Config: %+v\n", cfg)

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.Use(limit.MaxAllowed(20))

	// GET a password from the vault
	router.GET("/fetch/:safe/:account_name", func(c *gin.Context) {
		var (
			r           Result
			err         error
			status_code int
			result      gin.H
			pwv_safe    string
			msg         string
		)

		account_name := c.Param("account_name")
		safe := c.Param("safe")

		switch safe {
		case "managed":
			pwv_safe = cfg.PWVManagedSafe
		case "unmanaged":
			pwv_safe = cfg.PWVUnmanagedSafe
		}

		if pwv_safe == "" {
			msg = "Please specify a valid safe either \"managed\" or \"unmanaged\""
			log.Println(msg)
			status_code = http.StatusBadRequest
			result = gin.H{
				"result": nil,
				"error":  msg,
				"stderr": nil,
			}
		} else if isValidAccount_name(account_name) != true {
			msg = "Please specify a valid account_name"
			log.Println(msg)
			status_code = http.StatusBadRequest
			result = gin.H{
				"result": nil,
				"error":  msg,
				"stderr": nil,
			}
		} else {
			r, err = PWVCLICMD(cfg.PWVCLIPasswordSDK_CMD_timeout, cfg.PWVCLIPasswordSDK_CMD, cfg.PWVAppID, pwv_safe, account_name)

			if err != nil {
				status_code = http.StatusFailedDependency
				result = gin.H{
					"result": r.stdout,
					"error":  fmt.Sprintf("The process did NOT run successfully %s", err),
					"stderr": r.stderr,
				}
				goto Response
			}

			if r.exit_code > 0 {
				status_code = http.StatusFailedDependency
				result = gin.H{
					"result": r.stdout,
					"error":  fmt.Sprintf("According the return code [%d] the process did NOT run successfully", r.exit_code),
					"stderr": r.stderr,
				}
				goto Response
			}

			status_code = http.StatusOK
			result = gin.H{
				"result": r.stdout,
				"error":  err,
				"stderr": r.stderr,
			}
		}

	Response:
		if r.ok {
			log.Printf("|%4d |%14s | SUCCESS | STDOUT: %s, STDERR: %s", r.exit_code, r.elapsed, strings.Repeat("*", len(r.stdout)), r.stderr)
		} else {
			log.Printf("|%4d |%14s | FAILED  | STDOUT: %s, STDERR: %s, ERROR: %s", r.exit_code, r.elapsed, r.stdout, r.stderr, err)
		}
		c.JSON(status_code, result)
	})

	s := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.RouterAddress, cfg.RouterSocket),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   time.Millisecond*time.Duration(cfg.PWVCLIPasswordSDK_CMD_timeout) + 1*time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.ListenAndServe()

}
