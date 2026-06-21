package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shen060606/sma11sCan/global"
	"github.com/shen060606/sma11sCan/internal/api"
)

func main() {
	// 初始化数据库
	if err := global.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)

	}

	r := api.Setup()

	//下面的类似于r.run()
	srv := &http.Server{
		Addr:    ":8088",
		Handler: r,
	}

	go func() {
		fmt.Println("Server started on :8088")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	//等待ctrl+c
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGALRM)
	<-quit
	fmt.Println("\nShutting down ...")

	//给正在处理的请求 10 秒缓冲
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown:%v,err")
	}

	//关闭数据库
	sqlDB, _ := global.DB.DB()
	sqlDB.Close()

	fmt.Println("Server exited")
}
