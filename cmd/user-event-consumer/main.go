package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-event-driven/internal/user-event-consumer/service"
	"go-event-driven/pkg/config"
	"go-event-driven/pkg/kafka"
	"go-event-driven/pkg/logger"
)

func main() {
	cfg := config.LoadConfig()
	log := logger.GetLogger()

	log.Info("Waiting for Kafka to be ready...")
	time.Sleep(20 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	consumer := kafka.NewConsumer(
		cfg.KafkaBrokers(),
		"user-events",
		"user-event-consumer-group",
	)
	defer consumer.Close()

	eventHandler := service.NewUserEventHandler()

	go func() {
		log.Info("Starting user event consumer...")
		for {
			select {
			case <-ctx.Done():
				log.Info("Consumer context cancelled")
				return
			default:
				if err := consumer.Consume(ctx, eventHandler.HandleEvent); err != nil {
					log.WithError(err).Error("Consumer error, retrying in 5 seconds...")
					time.Sleep(5 * time.Second)
					continue
				}
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down user event consumer...")
	cancel()
}