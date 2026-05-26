//go:build windows

package main

import "os"

func notifyPause(_ chan os.Signal) {}
func resetPause(_ chan os.Signal)  {}
func suspendSelf()                 {}
