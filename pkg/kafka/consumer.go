package kafka

import (
	"context"
	"encoding/json"

	"go-event-driven/pkg/logger"

	"github.com/segmentio/kafka-go"
)

type Consumer struct {
	reader *kafka.Reader
}

type EventHandler func(event Event) error

func NewConsumer(brokers []string, topic string, groupID string) *Consumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})

	return &Consumer{reader: reader}
}

func (c *Consumer) Consume(ctx context.Context, handler EventHandler) error {
	log := logger.GetLogger()
	
	for {
		select {
		case <-ctx.Done():
			log.Info("Consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			message, err := c.reader.FetchMessage(ctx)
			if err != nil {
				log.WithError(err).Error("Failed to fetch message")
				continue
			}

			var event Event
			if err := json.Unmarshal(message.Value, &event); err != nil {
				log.WithError(err).Error("Failed to unmarshal event")
				if err := c.reader.CommitMessages(ctx, message); err != nil {
					log.WithError(err).Error("Failed to commit message after unmarshal error")
				}
				continue
			}

			if err := handler(event); err != nil {
				log.WithError(err).WithField("event_type", event.Type).Error("Failed to handle event")
				continue
			}

			if err := c.reader.CommitMessages(ctx, message); err != nil {
				log.WithError(err).Error("Failed to commit message")
				continue
			}

			log.WithField("event_type", event.Type).Info("Event processed successfully")
		}
	}
}

func (c *Consumer) Close() error {
	return c.reader.Close()
}