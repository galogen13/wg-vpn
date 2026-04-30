package main

import (
	"flag"
	"log"

	"wgvpn/internal/bot"
	"wgvpn/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/wgvpn/config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	b, err := bot.New(cfg)
	if err != nil {
		log.Fatalf("init bot: %v", err)
	}

	b.Run()
}
